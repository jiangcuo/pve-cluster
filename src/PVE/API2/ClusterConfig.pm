package PVE::API2::ClusterConfig;

use strict;
use warnings;

use PVE::Exception;
use PVE::Tools;
use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Cluster;
use PVE::APIClient::LWP;
use PVE::Corosync;
use PVE::Cluster::Setup;
use JSON;
use MIME::Base64;

use IO::Socket::UNIX;

use base qw(PVE::RESTHandler);

my $clusterconf = "/etc/pve/corosync.conf";
my $authfile = "/etc/corosync/authkey";
my $local_cluster_lock = "/var/lock/pvecm.lock";

my $nodeid_desc = {
    type => 'integer',
    description => "Node id for this node.",
    minimum => 1,
    optional => 1,
};
PVE::JSONSchema::register_standard_option("corosync-nodeid", $nodeid_desc);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {},
        },
        links => [{ rel => 'child', href => "{name}" }],
    },
    code => sub {
        my ($param) = @_;

        my $result = [
            { name => 'nodes' },
            { name => 'totem' },
            { name => 'join' },
            { name => 'qdevice' },
            { name => 'apiversion' },
	    { name => 'vmlist' },
            { name => 'joinable' },
            { name => 'accept-join' },
            { name => 'check-node' },
            { name => 'add-node' },
        ];

        return $result;
    },
});

__PACKAGE__->register_method({
    name => 'vmlist',
    path => 'vmlist',
    method => 'GET',
    description => "VM list with UUID support.",
    permissions => {
	check => ['perm', '/', [ 'Sys.Audit' ]],
    },
	protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
    },
    code => sub {
	my ($param) = @_;
    my $rpcenv = PVE::RPCEnvironment::get();
    my $authuser = $rpcenv->get_user();
    if ($authuser ne 'root@pam' && !PVE::AccessControl::verify_root_api_key($authuser)) {
        die "only root\@pam can access this API\n";
    }
	
	# 读取原始vmlist
	my $vmlist_content;
	my $vmlist_data;
	my $vmlist_path = '/etc/pve/.vmlist';

	if (open(my $fh, '<', $vmlist_path)) {
		local $/;
		$vmlist_content = <$fh>;
		close($fh);
		eval {
			$vmlist_data = decode_json($vmlist_content);
		};
		if ($@) {
			warn "cannot parse vmlist: $@";
			return {};
		}
	} else {
		warn "cannot open vmlist: $!";
		return {};
	}

	# 构建哈希对象输出，包含data数组
	my $vm_list = [];

	if ($vmlist_data && $vmlist_data->{ids}) {
		for my $vmid (keys %{$vmlist_data->{ids}}) {
			my $vm_info = $vmlist_data->{ids}->{$vmid};
			next unless $vm_info->{node} && $vm_info->{type};
			
			# 构建VM信息对象
			my $vm_entry = {
				vmid => int($vmid),
				node => $vm_info->{node},
				type => $vm_info->{type},
				version => $vm_info->{version} || 0
			};
			
			# 尝试读取UUID
			my $vm_type = $vm_info->{type} eq 'qemu' ? 'qemu-server' : $vm_info->{type};
			my $config_path = "/etc/pve/nodes/$vm_info->{node}/$vm_type/$vmid.conf";
			
			if (open(my $conf_fh, '<', $config_path)) {
				while (my $line = <$conf_fh>) {
					chomp $line;
					if ($line =~ /^uuid:\s*(.+)$/) {
						my $uuid = $1;
						$uuid =~ s/^\s+|\s+$//g;  # 去掉前后空格
						$vm_entry->{uuid} = $uuid if $uuid;
						last;
					}
				}
				close($conf_fh);
			}
			
			push @$vm_list, $vm_entry;
		}
	}

	# 返回哈希对象
	return 
		$vm_list;
    }});

__PACKAGE__->register_method({
    name => 'join_api_version',
    path => 'apiversion',
    method => 'GET',
    description => "Return the version of the cluster join API available on this node.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => 'integer',
        minimum => 0,
        description => "Cluster Join API version, currently "
            . PVE::Cluster::Setup::JOIN_API_VERSION,
    },
    code => sub {
        return PVE::Cluster::Setup::JOIN_API_VERSION;
    },
});

__PACKAGE__->register_method({
    name => 'create',
    path => '',
    method => 'POST',
    protected => 1,
    description => "Generate new cluster configuration. If no links given,"
        . " default to local IP address as link0.",
    parameters => {
        additionalProperties => 0,
        properties => PVE::Corosync::add_corosync_link_properties({
            clustername => {
                description => "The name of the cluster.",
                type => 'string',
                format => 'pve-node',
                maxLength => 15,
            },
            nodeid => get_standard_option('corosync-nodeid'),
            votes => {
                type => 'integer',
                description => "Number of votes for this node.",
                minimum => 1,
                optional => 1,
            },
        }),
    },
    returns => { type => 'string' },
    code => sub {
        my ($param) = @_;

        die "cluster config '$clusterconf' already exists\n" if -f $clusterconf;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $code = sub {
            STDOUT->autoflush();
            PVE::Cluster::Setup::setup_sshd_config(1);
            PVE::Cluster::Setup::setup_rootsshconfig();
            PVE::Cluster::Setup::setup_ssh_keys();

            PVE::Tools::run_command(['/usr/sbin/corosync-keygen', '-lk', $authfile])
                if !-f $authfile;
            die "no authentication key available\n" if -f !$authfile;

            my $nodename = PVE::INotify::nodename();

            # get the corosync basis config for the new cluster
            my $config = PVE::Corosync::create_conf($nodename, $param);

            print "Writing corosync config to /etc/pve/corosync.conf\n";
            PVE::Corosync::atomic_write_conf($config);

            my $local_ip_address = PVE::Cluster::remote_node_ip($nodename);
            PVE::Cluster::Setup::ssh_merge_keys();
            PVE::Cluster::Setup::gen_pve_node_files($nodename, $local_ip_address);
            PVE::Cluster::Setup::ssh_merge_known_hosts($nodename, $local_ip_address, 1);

            print "Restart corosync and cluster filesystem\n";
            PVE::Tools::run_command('systemctl restart corosync pve-cluster');
        };

        my $worker = sub {
            PVE::Tools::lock_file($local_cluster_lock, 10, $code);
            die $@ if $@;
        };

        return $rpcenv->fork_worker('clustercreate', $param->{clustername}, $authuser, $worker);
    },
});

__PACKAGE__->register_method({
    name => 'nodes',
    path => 'nodes',
    method => 'GET',
    description => "Corosync node list.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {
                node => { type => 'string' },
            },
        },
        links => [{ rel => 'child', href => "{node}" }],
    },
    code => sub {
        my ($param) = @_;

        my $conf = PVE::Cluster::cfs_read_file('corosync.conf');
        my $nodelist = PVE::Corosync::nodelist($conf);

        return PVE::RESTHandler::hash_to_array($nodelist, 'node');
    },
});

# lock method to ensure local and cluster wide atomicity
# if we're a single node cluster just lock locally, we have no other cluster
# node which we could contend with, else also acquire a cluster wide lock
my $config_change_lock = sub {
    my ($code) = @_;

    PVE::Tools::lock_file(
        $local_cluster_lock,
        10,
        sub {
            PVE::Cluster::cfs_update(1);
            my $members = PVE::Cluster::get_members();
            if (scalar(keys %$members) > 1) {
                my $res = PVE::Cluster::cfs_lock_file('corosync.conf', 10, $code);

                # cfs_lock_file only sets $@ but lock_file doesn't propagates $@ unless we die here
                die $@ if defined($@);

                return $res;
            } else {
                return $code->();
            }
        },
    );
};

__PACKAGE__->register_method({
    name => 'addnode',
    path => 'nodes/{node}',
    method => 'POST',
    protected => 1,
    description => "Adds a node to the cluster configuration. This call is for internal use.",
    parameters => {
        additionalProperties => 0,
        properties => PVE::Corosync::add_corosync_link_properties({
            node => get_standard_option('pve-node'),
            nodeid => get_standard_option('corosync-nodeid'),
            votes => {
                type => 'integer',
                description => "Number of votes for this node",
                minimum => 0,
                optional => 1,
            },
            force => {
                type => 'boolean',
                description => "Do not throw error if node already exists.",
                optional => 1,
            },
            new_node_ip => {
                type => 'string',
                description =>
                    "IP Address of node to add. Used as fallback if no links are given.",
                format => 'ip',
                optional => 1,
            },
            apiversion => {
                type => 'integer',
                description => 'The JOIN_API_VERSION of the new node.',
                optional => 1,
            },
        }),
    },
    returns => {
        type => "object",
        properties => {
            corosync_authkey => {
                type => 'string',
            },
            corosync_conf => {
                type => 'string',
            },
            warnings => {
                type => 'array',
                items => {
                    type => 'string',
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        $param->{apiversion} //= 0;
        PVE::Cluster::Setup::assert_node_can_join_our_version($param->{apiversion});

        PVE::Cluster::check_cfs_quorum();

        my $vc_errors;
        my $vc_warnings;

        my $code = sub {
            my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
            my $nodelist = PVE::Corosync::nodelist($conf);
            my $totem_cfg = PVE::Corosync::totem_config($conf);

            ($vc_errors, $vc_warnings) = PVE::Corosync::verify_conf($conf);
            die if scalar(@$vc_errors);

            my $name = $param->{node};

            # ensure we do not reuse an address, that can crash the whole cluster!
            my $check_duplicate_addr = sub {
                my $link = shift;
                return if !defined($link) || !defined($link->{address});
                my $addr = $link->{address};

                while (my ($k, $v) = each %$nodelist) {
                    next if $k eq $name; # allows re-adding a node if force is set

                    for my $linknumber (0 .. PVE::Corosync::MAX_LINK_INDEX) {
                        my $id = "ring${linknumber}_addr";
                        next if !defined($v->{$id});

                        die "corosync: address '$addr' already used on link $id by node '$k'\n"
                            if $v->{$id} eq $addr;
                    }
                }
            };

            my $links = PVE::Corosync::extract_corosync_link_args($param);
            foreach my $link (values %$links) {
                $check_duplicate_addr->($link);
            }

            # Make sure that the newly added node has links compatible with the
            # rest of the cluster. To start, extract all links that currently
            # exist. Check any node, all have the same links here (because of
            # verify_conf above).
            my $node_options = (values %$nodelist)[0];
            my $cluster_links = {};
            foreach my $opt (keys %$node_options) {
                my ($linktype, $linkid) = PVE::Corosync::parse_link_entry($opt);
                next if !defined($linktype);
                $cluster_links->{$linkid} = $node_options->{$opt};
            }

            # in case no fallback IP was passed, but instead only a single link,
            # treat it as fallback to allow link-IDs to be matched automatically
            # FIXME: remove in 8.0 or when joining an old node not supporting
            # new_node_ip becomes infeasible otherwise
            my $legacy_fallback = 0;
            if (!$param->{new_node_ip} && scalar(%$links) == 1 && $param->{apiversion} == 0) {
                my $passed_link_id = (keys %$links)[0];
                my $passed_link = delete $links->{$passed_link_id};
                $param->{new_node_ip} = $passed_link->{address};
                $legacy_fallback = 1;
            }

            if (scalar(%$links)) {
                # verify specified links exist and none are missing
                for my $linknum (0 .. PVE::Corosync::MAX_LINK_INDEX) {
                    my $have_cluster_link = defined($cluster_links->{$linknum});
                    my $have_new_link = defined($links->{$linknum});

                    die
                        "corosync: link $linknum exists in cluster config but wasn't specified for new node\n"
                        if $have_cluster_link && !$have_new_link;
                    die
                        "corosync: link $linknum specified for new node doesn't exist in cluster config\n"
                        if !$have_cluster_link && $have_new_link;
                }
            } else {
                # when called without any link parameters, fall back to
                # new_node_ip, if all existing nodes only have a single link too
                die "no links and no fallback ip (new_node_ip) given, cannot join cluster\n"
                    if !$param->{new_node_ip};

                my $cluster_link_count = scalar(%$cluster_links);
                if ($cluster_link_count == 1) {
                    my $linknum = (keys %$cluster_links)[0];
                    $links->{$linknum} = { address => $param->{new_node_ip} };
                } else {
                    die "cluster has $cluster_link_count links, but only 1 given"
                        if $legacy_fallback;
                    die "no links given but multiple links found on other nodes,"
                        . " fallback only supported on single-link clusters\n";
                }
            }

            if (defined(my $res = $nodelist->{$name})) {
                $param->{nodeid} = $res->{nodeid} if !$param->{nodeid};
                $param->{votes} = $res->{quorum_votes} if !defined($param->{votes});

                if (
                    $res->{quorum_votes} == $param->{votes}
                    && $res->{nodeid} == $param->{nodeid}
                    && $param->{force}
                ) {
                    print "forcing overwrite of configured node '$name'\n";
                } else {
                    die "can't add existing node '$name'\n";
                }
            } elsif (!$param->{nodeid}) {
                my $nodeid = 1;

                while (1) {
                    my $found = 0;
                    foreach my $v (values %$nodelist) {
                        if ($v->{nodeid} eq $nodeid) {
                            $found = 1;
                            $nodeid++;
                            last;
                        }
                    }
                    last if !$found;
                }

                $param->{nodeid} = $nodeid;
            }

            $param->{votes} = 1 if !defined($param->{votes});

            PVE::Cluster::Setup::gen_local_dirs($name);

            eval { PVE::Cluster::Setup::ssh_merge_keys(); };
            warn $@ if $@;

            $nodelist->{$name} = {
                nodeid => $param->{nodeid},
                name => $name,
            };
            $nodelist->{$name}->{quorum_votes} = $param->{votes} if $param->{votes};

            foreach my $link (keys %$links) {
                $nodelist->{$name}->{"ring${link}_addr"} = $links->{$link}->{address};
            }

            PVE::Cluster::log_msg('notice', 'root@pam', "adding node $name to cluster");

            PVE::Corosync::update_nodelist($conf, $nodelist);
        };

        $config_change_lock->($code);

        # If vc_errors is set, we died because of verify_conf.
        # Raise this error, since it contains more information than just a single-line string.
        if (defined($vc_errors) && scalar(@$vc_errors)) {
            my $err_hash = {};
            my $add_errs = sub {
                my ($type, @arr) = @_;
                return if !scalar(@arr);
                $err_hash->{"${type}$_"} = $arr[$_] for 0 .. $#arr;
            };

            $add_errs->("warning", @$vc_warnings);
            $add_errs->("error", @$vc_errors);

            PVE::Exception::raise("invalid corosync.conf\n", errors => $err_hash);
        }

        die $@ if $@;

        my $res = {
            corosync_authkey => PVE::Tools::file_get_contents($authfile),
            corosync_conf => PVE::Tools::file_get_contents($clusterconf),
            warnings => $vc_warnings,
        };

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'delnode',
    path => 'nodes/{node}',
    method => 'DELETE',
    protected => 1,
    description => "Removes a node from the cluster configuration.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $local_node = PVE::INotify::nodename();
        die "Cannot delete myself from cluster!\n" if $param->{node} eq $local_node;

        PVE::Cluster::check_cfs_quorum();

        my $code = sub {
            my $conf = PVE::Cluster::cfs_read_file("corosync.conf");
            my $nodelist = PVE::Corosync::nodelist($conf);

            my $node;
            my $nodeid;

            foreach my $tmp_node (keys %$nodelist) {
                my $d = $nodelist->{$tmp_node};
                my $ring0_addr = $d->{ring0_addr};
                my $ring1_addr = $d->{ring1_addr};
                if (
                    ($tmp_node eq $param->{node})
                    || (defined($ring0_addr) && ($ring0_addr eq $param->{node}))
                    || (defined($ring1_addr) && ($ring1_addr eq $param->{node}))
                ) {
                    $node = $tmp_node;
                    $nodeid = $d->{nodeid};
                    last;
                }
            }

            die "Node/IP: $param->{node} is not a known host of the cluster.\n"
                if !defined($node);

            PVE::Cluster::log_msg('notice', 'root@pam', "deleting node $node from cluster");

            delete $nodelist->{$node};

            # allowed to fail when node is already shut down!
            eval {
                PVE::Tools::run_command(['corosync-cfgtool', '-k', $nodeid])
                    if defined($nodeid);
            };

            PVE::Corosync::update_nodelist($conf, $nodelist);
        };

        $config_change_lock->($code);
        die $@ if $@;

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'join_info',
    path => 'join',
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    method => 'GET',
    description => "Get information needed to join this cluster over the connected node.",
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option(
                'pve-node',
                {
                    description => "The node for which the joinee gets the nodeinfo. ",
                    default => "current connected node",
                    optional => 1,
                },
            ),
        },
    },
    returns => {
        type => 'object',
        additionalProperties => 0,
        properties => {
            nodelist => {
                type => 'array',
                items => {
                    type => "object",
                    additionalProperties => 1,
                    properties => {
                        name => get_standard_option('pve-node'),
                        nodeid => get_standard_option('corosync-nodeid'),
                        ring0_addr => get_standard_option('corosync-link'),
                        quorum_votes => { type => 'integer', minimum => 0 },
                        pve_addr => { type => 'string', format => 'ip' },
                        pve_fp => get_standard_option('fingerprint-sha256'),
                    },
                },
            },
            preferred_node => get_standard_option('pve-node'),
            totem => { type => 'object' },
            config_digest => { type => 'string' },
        },
    },
    code => sub {
        my ($param) = @_;

        my $nodename = $param->{node} // PVE::INotify::nodename();

        PVE::Cluster::cfs_update(1);
        my $conf = PVE::Cluster::cfs_read_file('corosync.conf');

        # FIXME: just return undef or empty object in PVE 8.0 (check if manager can handle it!)
        PVE::Exception::raise(
            'node is not in a cluster, no join info available!',
            code => HTTP::Status::HTTP_FAILED_DEPENDENCY,
        ) if !($conf && $conf->{main});

        my $totem_cfg = $conf->{main}->{totem} // {};
        my $nodelist = $conf->{main}->{nodelist}->{node} // {};
        my $corosync_config_digest = $conf->{digest};

        die "unknown node '$nodename'\n" if !$nodelist->{$nodename};

        foreach my $name (keys %$nodelist) {
            my $node = $nodelist->{$name};
            $node->{pve_fp} = PVE::Cluster::get_node_fingerprint($name);
            $node->{pve_addr} = scalar(PVE::Cluster::remote_node_ip($name));
        }

        my $res = {
            nodelist => [values %$nodelist],
            preferred_node => $nodename,
            totem => $totem_cfg,
            config_digest => $corosync_config_digest,
        };

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'join',
    path => 'join',
    method => 'POST',
    protected => 1,
    description => "Joins this node into an existing cluster. If no links are"
        . " given, default to IP resolved by node's hostname on single"
        . " link (fallback fails for clusters with multiple links).",
    parameters => {
        additionalProperties => 0,
        properties => PVE::Corosync::add_corosync_link_properties({
            hostname => {
                type => 'string',
                description => "Hostname (or IP) of an existing cluster member.",
            },
            nodeid => get_standard_option('corosync-nodeid'),
            votes => {
                type => 'integer',
                description => "Number of votes for this node",
                minimum => 0,
                optional => 1,
            },
            force => {
                type => 'boolean',
                description => "Do not throw error if node already exists.",
                optional => 1,
            },
            fingerprint => get_standard_option('fingerprint-sha256'),
            password => {
                description => "Superuser (root) password of peer node.",
                type => 'string',
                maxLength => 128,
            },
        }),
    },
    returns => { type => 'string' },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $worker = sub {
            STDOUT->autoflush();
            PVE::Tools::lock_file($local_cluster_lock, 10, \&PVE::Cluster::Setup::join, $param);
            die $@ if $@;
        };

        return $rpcenv->fork_worker('clusterjoin', undef, $authuser, $worker);
    },
});

# Adding a node from the cluster side: a cluster node checks the new node ('check-node'), adds it to
# the corosync configuration and sends the configuration to the new node ('add-node'), which then
# finishes joining ('joinable' and 'accept-join' on the new node).

my $remote_error = sub {
    my ($err) = @_;

    if (ref($err) && $err->isa('PVE::APIClient::Exception')) {
        my $msg = $err->{msg} // "$err";
        chomp $msg;
        $msg = "authentication failure" if ($err->{code} // 0) == 401;
        my $errors = $err->{errors} // {};
        $msg .= join('', map { "\n$errors->{$_}" } sort keys %$errors);
        return "$msg\n";
    }
    return $err;
};

my $cluster_link_ids = sub {
    my ($nodelist) = @_;

    # all nodes have the same links, see PVE::Corosync::verify_conf
    my $node = (values %$nodelist)[0] // {};
    my $ids = [];
    for my $opt (keys %$node) {
        my ($type, $id) = PVE::Corosync::parse_link_entry($opt);
        push @$ids, int($id) if defined($type);
    }
    return [sort { $a <=> $b } @$ids];
};

my $remote_node_properties = {
    address => {
        type => 'string',
        format => 'address',
        description => "IP address or hostname of the node to add.",
    },
    password => {
        type => 'string',
        description => "Superuser (root) password of the node to add.",
        maxLength => 128,
    },
    fingerprint => get_standard_option('fingerprint-sha256'),
};

__PACKAGE__->register_method({
    name => 'joinable',
    path => 'joinable',
    method => 'GET',
    protected => 1,
    description => "Check if this node can be added to a cluster by a cluster node."
        . " This call is for internal use.",
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => 'object',
        properties => {
            nodename => get_standard_option('pve-node'),
            ip => {
                type => 'string',
                optional => 1,
            },
            apiversion => {
                type => 'integer',
                description => 'The JOIN_API_VERSION of this node.',
            },
            errors => {
                type => 'array',
                items => { type => 'string' },
                description => 'Problems preventing this node from joining a cluster.',
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $nodename = PVE::INotify::nodename();
        my $ip = eval { scalar(PVE::Cluster::remote_node_ip($nodename)) };

        return {
            nodename => $nodename,
            defined($ip) ? (ip => $ip) : (),
            apiversion => PVE::Cluster::Setup::JOIN_API_VERSION,
            errors => PVE::Cluster::Setup::check_joinable($ip, {}),
        };
    },
});

__PACKAGE__->register_method({
    name => 'accept_join',
    path => 'accept-join',
    method => 'POST',
    protected => 1,
    description => "Join a cluster with the configuration of a cluster node, which already added"
        . " this node. This call is for internal use.",
    parameters => {
        additionalProperties => 0,
        properties => {
            corosync_conf => {
                type => 'string',
                description => 'The corosync configuration of the cluster.',
                maxLength => 128 * 1024,
            },
            corosync_authkey => {
                type => 'string',
                description => 'The base64 encoded corosync authentication key.',
                maxLength => 64 * 1024,
            },
            apiversion => {
                type => 'integer',
                description => 'The JOIN_API_VERSION of the cluster node.',
            },
        },
    },
    returns => { type => 'string' },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        PVE::Cluster::Setup::assert_we_can_join_cluster_version($param->{apiversion});

        my $nodename = PVE::INotify::nodename();
        my $corosync_conf = $param->{corosync_conf};
        my $corosync_authkey = decode_base64($param->{corosync_authkey});
        die "invalid corosync authentication key\n" if !length($corosync_authkey);

        # check before doing anything, so that the cluster node can revert adding this node
        my $links = PVE::Cluster::Setup::get_node_links_from_conf($corosync_conf, $nodename);
        my $ip = eval { scalar(PVE::Cluster::remote_node_ip($nodename)) };
        my $errors = PVE::Cluster::Setup::check_joinable($ip, $links);
        die "node cannot join the cluster:\n" . join('', map { "* $_\n" } @$errors)
            if scalar(@$errors);

        my $worker = sub {
            STDOUT->autoflush();
            PVE::Tools::lock_file(
                $local_cluster_lock,
                10,
                \&PVE::Cluster::Setup::accept_join,
                $corosync_conf,
                $corosync_authkey,
            );
            die $@ if $@;
        };

        return $rpcenv->fork_worker('clusterjoin', undef, $authuser, $worker);
    },
});

__PACKAGE__->register_method({
    name => 'check_node',
    path => 'check-node',
    method => 'POST',
    protected => 1,
    description => "Check if a node can be added to the cluster. Without fingerprint, only the"
        . " certificate fingerprint of the node is returned, which must be confirmed before"
        . " sending the password.",
    parameters => {
        additionalProperties => 0,
        properties => {
            address => $remote_node_properties->{address},
            password => { $remote_node_properties->{password}->%*, optional => 1 },
            fingerprint => get_standard_option('fingerprint-sha256', { optional => 1 }),
        },
    },
    returns => {
        type => 'object',
        properties => {
            fingerprint => get_standard_option('fingerprint-sha256'),
            nodename => get_standard_option('pve-node', { optional => 1 }),
            ip => {
                type => 'string',
                optional => 1,
            },
            version => {
                type => 'string',
                optional => 1,
            },
            errors => {
                type => 'array',
                items => { type => 'string' },
                optional => 1,
            },
            addresses => {
                type => 'array',
                items => {
                    type => 'object',
                    properties => {
                        iface => { type => 'string' },
                        address => { type => 'string' },
                    },
                },
                optional => 1,
            },
            links => {
                type => 'array',
                items => { type => 'integer' },
                description => 'The corosync links of the cluster.',
                optional => 1,
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $conf = PVE::Cluster::cfs_read_file('corosync.conf');
        die "this node is not in a cluster\n" if !($conf && $conf->{main});

        my $address = $param->{address};
        my $fingerprint = $param->{fingerprint};
        if (!$fingerprint) {
            return { fingerprint => PVE::Cluster::Setup::get_remote_fingerprint($address) };
        }

        die "password is required\n" if !defined($param->{password});

        my ($conn, $info);
        eval {
            $conn = PVE::Cluster::Setup::remote_connect(
                $address, $param->{password}, [$fingerprint],
            );
            $info = $conn->get('/cluster/config/joinable');
        };
        if (my $err = $@) {
            die "node does not support being added by a cluster node, please upgrade it\n"
                if ref($err) && ($err->{code} // 0) == 501;
            die $remote_error->($err);
        }

        my $nodename = $info->{nodename};
        my $errors = [$info->{errors}->@*];

        my $nodelist = PVE::Corosync::nodelist($conf) // {};
        push @$errors, "a node named '$nodename' is already part of the cluster"
            if $nodelist->{$nodename};

        eval { PVE::Cluster::Setup::assert_node_can_join_our_version($info->{apiversion}) };
        push @$errors, $@ =~ s/\n+$//r if $@;

        my $version = eval { $conn->get('/version') } // {};

        my $addresses = [];
        my $interfaces = eval { $conn->get("/nodes/$nodename/network") } // [];
        for my $iface (sort { $a->{iface} cmp $b->{iface} } @$interfaces) {
            for my $key ('address', 'address6') {
                my $addr = $iface->{$key} // next;
                push @$addresses, { iface => $iface->{iface}, address => $addr };
            }
        }

        return {
            fingerprint => $fingerprint,
            nodename => $nodename,
            defined($info->{ip}) ? (ip => $info->{ip}) : (),
            defined($version->{version}) ? (version => $version->{version}) : (),
            errors => $errors,
            addresses => $addresses,
            links => $cluster_link_ids->($nodelist),
        };
    },
});

__PACKAGE__->register_method({
    name => 'add_node',
    path => 'add-node',
    method => 'POST',
    protected => 1,
    description => "Add a node to the cluster. The node must not be part of a cluster and must"
        . " not contain guests. If no links are given, the IP of the node's hostname is used on"
        . " a single link cluster.",
    parameters => {
        additionalProperties => 0,
        properties => PVE::Corosync::add_corosync_link_properties({
            $remote_node_properties->%*,
            nodeid => get_standard_option('corosync-nodeid'),
            votes => {
                type => 'integer',
                description => "Number of votes for this node",
                minimum => 0,
                optional => 1,
            },
        }),
    },
    returns => { type => 'string' },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $address = $param->{address};
        my $password = $param->{password};
        my $fingerprint = $param->{fingerprint};

        my $worker = sub {
            STDOUT->autoflush();

            print "Establishing API connection with '$address'\n";
            my ($conn, $info);
            eval {
                $conn = PVE::Cluster::Setup::remote_connect($address, $password, [$fingerprint]);
                $info = $conn->get('/cluster/config/joinable');
            };
            die $remote_error->($@) if $@;

            my $nodename = $info->{nodename};
            print "Adding node '$nodename'\n";

            die "node '$nodename' cannot join a cluster:\n"
                . join('', map { "* $_\n" } $info->{errors}->@*)
                if scalar($info->{errors}->@*);

            my $args = {
                node => $nodename,
                apiversion => $info->{apiversion},
            };
            $args->{nodeid} = $param->{nodeid} if $param->{nodeid};
            $args->{votes} = $param->{votes} if defined($param->{votes});
            my $links = PVE::Corosync::extract_corosync_link_args($param);
            for my $link (keys %$links) {
                $args->{"link$link"} = PVE::Corosync::print_corosync_link($links->{$link});
            }
            if (!%$links) {
                die "no links given and node '$nodename' has no IP to fall back to\n"
                    if !$info->{ip};
                print "No cluster network links passed explicitly, fallback to the node's IP"
                    . " '$info->{ip}'\n";
                $args->{new_node_ip} = $info->{ip};
            }

            my $conf = PVE::Cluster::cfs_read_file('corosync.conf');
            my $node_count = scalar(keys %{ PVE::Corosync::nodelist($conf) // {} });

            print "Adding node '$nodename' to the cluster configuration\n";
            my $res = __PACKAGE__->addnode($args);
            warn "cluster: $_\n" for ($res->{warnings} // [])->@*;

            print "Sending the cluster configuration to '$nodename'\n";
            my $upid = eval {
                $conn->post(
                    '/cluster/config/accept-join',
                    {
                        corosync_conf => $res->{corosync_conf},
                        corosync_authkey => encode_base64($res->{corosync_authkey}, ''),
                        apiversion => PVE::Cluster::Setup::JOIN_API_VERSION,
                    },
                );
            };
            if (my $err = $@) {
                warn "node '$nodename' did not accept the cluster configuration, reverting\n";
                eval {
                    # a single node cluster lost quorum by adding the node
                    if ($node_count == 1 && !PVE::Cluster::check_cfs_quorum(1)) {
                        PVE::Tools::run_command(['corosync-quorumtool', '-e', '1']);
                        for (1 .. 10) {
                            last if PVE::Cluster::check_cfs_quorum(1);
                            sleep(1);
                        }
                    }
                    __PACKAGE__->delnode({ node => $nodename });
                };
                warn "removing node '$nodename' from the cluster configuration failed - $@" if $@;
                die $remote_error->($err);
            }

            print "Node '$nodename' is joining the cluster\n";

            # The node restarts its cluster services and gets a new certificate signed by the
            # cluster CA while joining, reconnect and also trust the new certificate then.
            my $reconnect = sub {
                my $fingerprints = [$fingerprint];
                if (my $new = eval { PVE::Cluster::get_node_fingerprint($nodename) }) {
                    push @$fingerprints, $new;
                }
                $conn = PVE::Cluster::Setup::remote_connect($address, $password, $fingerprints);
            };

            my $deadline = time() + 15 * 60;
            my $start = 0;
            my $status;
            while (1) {
                my $log;
                eval {
                    $status = $conn->get("/nodes/$nodename/tasks/$upid/status");
                    $log = $conn->get(
                        "/nodes/$nodename/tasks/$upid/log",
                        { start => $start, limit => 500 },
                    );
                };
                if (my $err = $@) {
                    die "lost connection to '$nodename' - " . $remote_error->($err)
                        if time() > $deadline;
                    sleep(2);
                    eval { $reconnect->() };
                    next;
                }

                for my $line (@$log) {
                    print "$nodename: $line->{t}\n";
                    $start = $line->{n};
                }
                last if $status->{status} ne 'running';

                die "timeout waiting for '$nodename' to join the cluster\n" if time() > $deadline;
                sleep(1);
            }

            my $exitstatus = $status->{exitstatus} // 'unknown';
            die "joining the cluster failed on '$nodename': $exitstatus\n" if $exitstatus ne 'OK';

            print "Successfully added node '$nodename' to the cluster\n";
        };

        return $rpcenv->fork_worker('clusteradd', undef, $authuser, $worker);
    },
});

__PACKAGE__->register_method({
    name => 'totem',
    path => 'totem',
    method => 'GET',
    description => "Get corosync totem protocol settings.",
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => "object",
        properties => {},
    },
    code => sub {
        my ($param) = @_;

        my $conf = PVE::Cluster::cfs_read_file('corosync.conf');

        my $totem_cfg = $conf->{main}->{totem};

        return $totem_cfg;
    },
});

__PACKAGE__->register_method({
    name => 'status',
    path => 'qdevice',
    method => 'GET',
    protected => 1,
    description => 'Get QDevice status',
    permissions => {
        check => ['perm', '/', ['Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {},
    },
    returns => {
        type => "object",
    },
    code => sub {
        my ($param) = @_;

        my $result = {};
        my $socket_path = "/var/run/corosync-qdevice/corosync-qdevice.sock";
        return $result if !-S $socket_path;

        my $qdevice_socket = IO::Socket::UNIX->new(
            Type => SOCK_STREAM,
            Peer => $socket_path,
        );

        print $qdevice_socket "status verbose\n";
        my $qdevice_keys = {
            "Algorithm" => 1,
            "Echo reply" => 1,
            "Last poll call" => 1,
            "Model" => 1,
            "QNetd host" => 1,
            "State" => 1,
            "Tie-breaker" => 1,
        };
        while (my $line = <$qdevice_socket>) {
            chomp $line;
            next if $line =~ /^\s/;
            if ($line =~ /^(.*?)\s*:\s*(.*)$/) {
                $result->{$1} = $2 if $qdevice_keys->{$1};
            }
        }

        return $result;
    },
});
#TODO: possibly add setup and remove methods

1;
