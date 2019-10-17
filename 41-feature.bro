global conn_index: count = 1;

redef enum Log::ID += {LOG};

type features: record {
	index: count				&log;
	start_time: time			&log;
	src_addr: addr				&log;
	src_port: count				&log;
	dst_addr: addr				&log;
	dst_port: count				&log;
	duration: string			&default = "0" &log;
	src_size: count				&default = 0 &log;
	dst_size: count				&default = 0 &log;
	protocol_type: string		&default = "tcp" &log;
	land: bool					&default = F &log;
	service: string				&default = "other" &log;
	flag: string				&default = "SF" &log;
	wrong_fragment: count		&default = 0 &log;
	urgent: count				&default = 0 &log;
	hot: count					&default = 0 &log;
	num_failed_logins: count	&default = 0 &log;
	logged_in: bool				&default = F &log;
	num_compromised: count		&default = 0 &log;
	root_shell: bool			&default = F &log;
	su_attempted: bool			&default = F &log;
	num_root: count				&default = 0 &log;
	num_file_creations: count	&default = 0 &log;
	num_shells: count			&default = 0 &log;
	num_access_files: count		&default = 0 &log;
	num_outbound_files: count	&default = 0 &log;
	is_hot_login: bool			&default = F &log;
	is_guest_login: bool		&default = F &log;
};

global conn_to_feature: table[time, interval, addr, count, addr, count] of features;


################# global functions #################

function get_flag(c: connection): string {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	local protocol = get_port_transport_proto(c$id$resp_p);
	local os = c$orig$state;
	local rs = c$resp$state;

	local o_inactive = (os == TCP_INACTIVE || os == TCP_PARTIAL);
	local r_inactive = (rs == TCP_INACTIVE || rs == TCP_PARTIAL);

	if (protocol == tcp) {
		if (rs == TCP_RESET) {
			if (os == TCP_SYN_SENT || os == TCP_SYN_ACK_SENT || (os == TCP_RESET && c$orig$size == 0 && c$resp$size == 0)) {
				return "REJ";
			} else if (o_inactive)
				return "RSTRH";
			else {
				return "RSTR";
			}
		} else if (os == TCP_RESET) {
			return (r_inactive ? "RSTOS0" : "RSTO");
		} else if (rs == TCP_CLOSED && os == TCP_CLOSED) {
			return "SF";
		} else if (os == TCP_CLOSED) {
			return (r_inactive ? "SH" : "S2");
		} else if (rs == TCP_CLOSED) {
			return (o_inactive ? "SHR" : "S3");
		} else if (os == TCP_SYN_SENT && rs == TCP_INACTIVE) {
			return "S0";
		} else if (os == TCP_ESTABLISHED && rs == TCP_ESTABLISHED) {
			return "S1";
		} else {
			# origin: OTH
			return "SF";
		}
	} else if (protocol == udp) {
		if (os == UDP_ACTIVE) {
			return (rs == UDP_ACTIVE ? "SF" : "S0");
		} else {
		return (rs == UDP_ACTIVE ? "SHR" : "OTH");
		}
	} else if (protocol == icmp) {
		if (c$orig$size > 0) {
			if (c$resp$size > 0) {
				return "SF";
		  	} else {
		  		return "SH";
		  	}
		} else if (c$resp$size > 0) {
			return "SHR";
		} else {
			return "OTH";
		}
	} else {
		return "OTH";
	}
}

function add_record(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	if ([conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port] !in conn_to_feature) {
		local conn_src_size = c$orig$size;
		local conn_dst_size = c$resp$size;
		local conn_protocol: string;
		local conn_src_equal_dst: bool;
		local conn_service: string;

		switch (get_port_transport_proto(c$id$resp_p)) {
		case tcp:
			conn_protocol = "tcp";
			break;
		case udp:
			conn_protocol = "udp";
			break;
		case icmp:
			conn_protocol = "icmp";
			break;
		default:
			conn_protocol = "unknown";
			break;
		}
		if (conn_src_port == conn_dst_port && conn_src_addr == conn_dst_addr) {
			conn_src_equal_dst = T;
		} else {
			conn_src_equal_dst = F;
		}
		switch conn_dst_port {
		case 113:
			conn_service = "auth";
			break;
		case 179:
			conn_service = "bgp";
			break;
		case 530:
			conn_service = "courier";
			break;
		case 105:
			conn_service = "csnet_ns";
			break;
		case 84:
			conn_service = "ctf";
			break;
		case 13:
			conn_service = "daytime";
			break;
		case 9:
			conn_service = "discard";
			break;
		case 53:
			conn_service = "domain";
			break;
		case 4:
			conn_service = "echo";
			break;
		case 520:
			conn_service = "efs";
			break;
		case 512:
			conn_service = "exec";
			break;
		case 79:
			conn_service = "finger";
			break;
		case 21:
			conn_service = "ftp";
			break;
		case 20:
			conn_service = "ftp_data";
			break;
		case 70:
			conn_service = "gopher";
			break;
		case 101:
			conn_service = "hostnames";
			break;
		case 80:
			conn_service = "http";
			break;
		case 2784:
			conn_service = "http_2784";
			break;
		case 443:
			conn_service = "http_443";
			break;
		case 8001:
			conn_service = "http_8001";
			break;
		case 194:
			conn_service = "IRC";
			break;
		case 102:
			conn_service = "iso_tsap";
			break;
		case 543:
			conn_service = "klogin";
			break;
		case 544:
			conn_service = "kshell";
			break;
		case 389:
			conn_service = "ldap";
			break;
		case 245:
			conn_service = "link";
			break;
		case 513:
			conn_service = "login";
			break;
		case 1911:
			conn_service = "mtp";
			break;
		case 138:
			conn_service = "netbios_dgm";
			break;
		case 137:
			conn_service = "netbios_ns";
			break;
		case 139:
			conn_service = "netbios_ssn";
			break;
		case 15:
			conn_service = "netstat";
			break;
		case 119:
			conn_service = "nntp";
			break;
		case 109:
			conn_service = "pop_2";
			break;
		case 110:
			conn_service = "pop_3";
			break;
		case 515:
			conn_service = "printer";
			break;
		case 24:
			conn_service = "private";
			break;
		case 35:
			conn_service = "private";
			break;
		case 57:
			conn_service = "private";
			break;
		case 59:
			conn_service = "private";
			break;
		case 75:
			conn_service = "private";
			break;
		case 77:
			conn_service = "private";
			break;
		case 87:
			conn_service = "private";
			break;
		case 71:
			conn_service = "remote_job";
			break;
		case 72:
			conn_service = "remote_job";
			break;
		case 73:
			conn_service = "remote_job";
			break;
		case 74:
			conn_service = "remote_job";
			break;
		case 5:
			conn_service = "rje";
			break;
		case 514:
			conn_service = "shell";
			break;
		case 25:
			conn_service = "smtp";
			break;
		case 66:
			conn_service = "sql_net";
			break;
		case 22:
			conn_service = "ssh";
			break;
		case 111:
			conn_service = "sunrpc";
			break;
		case 95:
			conn_service = "supdup";
			break;
		case 11:
			conn_service = "systat";
			break;
		case 23:
			conn_service = "telnet";
			break;
		case 69:
			conn_service = "tftp_u";
			break;
		case 37:
			conn_service = "time";
			break;
		case 540:
			conn_service = "uucp";
			break;
		case 117:
			conn_service = "uucp_path";
			break;
		case 63:
			conn_service = "whois";
			break;
		case 43:
			conn_service = "whois";
			break;
		case 6000:
			conn_service = "X11";
			break;
		case 210:
			conn_service = "Z39_50";
			break;
		default:
			conn_service = "http";
			break;
		}

		conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port] = [
			$index = conn_index,
			$start_time = conn_start,
			$src_addr = conn_src_addr,
			$src_port = conn_src_port,
			$dst_addr = conn_dst_addr,
			$dst_port = conn_dst_port,
			$duration = fmt("%.0f", conn_duration),
			$src_size = conn_src_size,
			$dst_size = conn_dst_size,
			$protocol_type = conn_protocol,
			$land = conn_src_equal_dst,
			$service = conn_service,
			$flag = get_flag(c)
		];
		++conn_index;
	} else {
		conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$flag = get_flag(c);
	}
}


################# set attributes #################

function set_logged_in_T(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$logged_in = T;
}

function set_wrong_fragment_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$wrong_fragment;
}

function set_urgent_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$urgent;
}

function set_hot_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$hot;
}

function set_num_failed_logins_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_failed_logins;
}

function set_num_compromised_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_compromised;
}

function set_root_shell_T(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$root_shell = T;
}

function set_su_attempted_T(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$su_attempted = T;
}

function set_num_root_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_root;
}

function set_num_file_creations_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_file_creations;
}

function set_num_shells_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_shells;
}

function set_num_access_files_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_access_files;
}

function set_num_outbound_files_increase(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	++conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$num_outbound_files;
}

function set_is_hot_login_T(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$is_hot_login = T;
}

function set_is_guest_login_T(c: connection) {
	local conn_start = c$start_time;
	local conn_duration = c$duration;
	local conn_src_addr = c$id$orig_h;
	local conn_src_port = port_to_count(c$id$orig_p);
	local conn_dst_addr = c$id$resp_h;
	local conn_dst_port = port_to_count(c$id$resp_p);

	conn_to_feature[conn_start, conn_duration, conn_src_addr, conn_src_port, conn_dst_addr, conn_dst_port]$is_guest_login = T;
}


################# useful events #################

event new_connection(c: connection) {
	add_record(c);
}

event connection_state_remove(c: connection) {
	add_record(c);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
	add_record(c);
}

event udp_contents(c: connection, is_orig: bool, contents: string) {
	add_record(c);
}

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string) {
	add_record(c);
}

event icmp_echo_reply(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string) {
	add_record(c);
}

event icmp_unreachable(c: connection, icmp: icmp_conn, code: count, context: icmp_context) {
	add_record(c);
}

event icmp_time_exceeded(c: connection, icmp: icmp_conn, code: count, context: icmp_context) {
	add_record(c);
}

event packet_contents(c: connection, contents: string) {
	add_record(c);
}

event new_packet(c: connection, p: pkt_hdr) {
	add_record(c);
	if (get_port_transport_proto(c$id$resp_p) == tcp && p$tcp$flags >= 32) {
		set_urgent_increase(c);
	}
}

event login_input_line(c: connection, line: string) {
	add_record(c);
	### hot list
	if (("cd " in line) && ("dir" !in line)) { # try to enter in system directories
		set_hot_increase(c);
	}
	if (/"gcc "|"g++ "/ in line) { # create program
		set_hot_increase(c);
		set_num_file_creations_increase(c);
	}
	if (/^".\/"/ in line) { # run program
		set_hot_increase(c);
	}
	if (/^"\/tmp\/"[0-9]+/ in line) { # try to enter in /tmp/ directory
		set_hot_increase(c);
	}
	# sensitive files
	if (/"a.out"|"auditd"|"automountd"|"cron"|"find"|"fsck"|"ftp"|"in.comsat"|"inetd"|"in.telnetd"|"kerbd"|"keyserv"|"lockd"|"login"|"login"|"lp.cat"|"lpNet"|"lpsched"|"lp.tell"|"lynx"|"mail"|"man"|"mlp"|"more"|"netscape"|"nscd"|"primes"|"sh"|"sleep"|"sshd"|"statd"|"syslogd"|"tcsh"|"telnet"|"tex"|"top"|"ttymon"|"vi"|"vold"|"xntpd"/ in line) {
		set_hot_increase(c);
	}

	### su attempted
	if ("su " in line) {
		set_su_attempted_T(c);
	}

	### create files
	if ("[New file]" in line) {
		set_num_file_creations_increase(c);
	}

	### num_access_files
	if (/"cat "|"vi "|"rm "/ in line) {
		set_num_access_files_increase(c);
	}

	### hot login
	if (/"su - root"|^[0-9]*"root"|"admin"/ in line) {
		set_is_hot_login_T(c);
	}
	### guest login
	if (/guest|anonymous|[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+/i in line) {
		set_is_guest_login_T(c);
	}
}

event login_output_line(c: connection, line: string) {
	add_record(c);
	if ("Login incorrect" in line) {
		set_num_failed_logins_increase(c);
	}
	if ("not found" in line) {
		set_num_compromised_increase(c);
	}
	if (/^"root@"/ in line) {
		set_root_shell_T(c);
		set_num_root_increase(c);
	}
	if (/"gcc "|"g++ "|"mv "|"cp "|"cat "/ in line) {
		set_num_file_creations_increase(c);
	}
	if (/^"Last login:"/ in line) {
		set_num_shells_increase(c);
	}
}

event login_failure(c: connection, user: string, client_user: string, password: string, line: string) {
	add_record(c);
	set_num_failed_logins_increase(c);
}

event login_success(c: connection, user: string, client_user: string, password: string, line: string) {
	add_record(c);
	set_logged_in_T(c);
	if (/"su - root"|^[0-9]*"root"|"admin"/ in user) {
		set_is_hot_login_T(c);
	}
	if (/guest|anonymous|[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+/i in user) {
		set_is_guest_login_T(c);
	}
}

event login_terminal(c: connection, terminal: string) {
	add_record(c);
	set_logged_in_T(c);
	if (/"su - root"|^[0-9]*"root"|"admin"/ in terminal) {
		set_is_hot_login_T(c);
	}
	if (/guest|anonymous|[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+/i in terminal) {
		set_is_guest_login_T(c);
	}
}

event login_display(c: connection, display: string) {
	add_record(c);
	set_logged_in_T(c);
	if (/"su - root"|^[0-9]*"root"|"admin"/ in display) {
		set_is_hot_login_T(c);
	}
	if (/guest|anonymous|[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+/i in display) {
		set_is_guest_login_T(c);
	}
}

event login_prompt(c: connection, prompt: string) {
	add_record(c);
	set_logged_in_T(c);
	set_root_shell_T(c);
	if (/"su - root"|^[0-9]*"root"|"admin"/ in prompt) {
		set_is_hot_login_T(c);
	}
	if (/guest|anonymous|[a-z0-9]+@[a-z0-9]+\.[a-z0-9]+/i in prompt) {
		set_is_guest_login_T(c);
	}
}

event ssh_signature_found(c: connection, is_orig: bool) {
	add_record(c);
}

event telnet_signature_found(c: connection, is_orig: bool, len: count) {
	add_record(c);
}

event rlogin_signature_found(c: connection, is_orig: bool, num_null: count, len: count) {
	add_record(c);
}

event root_backdoor_signature_found(c: connection) {
	add_record(c);
}

event ftp_signature_found(c: connection) {
	add_record(c);
}

event napster_signature_found(c: connection) {
	add_record(c);
}

event gnutella_signature_found(c: connection) {
	add_record(c);
}

event kazaa_signature_found(c: connection) {
	add_record(c);
}

event http_signature_found(c: connection) {
	add_record(c);
}

event http_proxy_signature_found(c: connection) {
	add_record(c);
}

event smtp_signature_found(c: connection) {
	add_record(c);
}

event irc_signature_found(c: connection) {
	add_record(c);
}

event gaobot_signature_found(c: connection) {
	add_record(c);
}

event finger_request(c: connection, full: bool, username: string, hostname: string) {
	add_record(c);
}

event ident_reply(c: connection, lport: port, rport: port, user_id: string, system: string) {
	add_record(c);
}

event rsh_request(c: connection, client_user: string, server_user: string, line: string, new: bool) {
	add_record(c);
}

event rsh_reply(c: connection, client_user: string, server_user: string, line: string) {
	add_record(c);
}

event pop3_login_success(c: connection, is_orig: bool, user: string, password: string) {
	add_record(c);
}

event pop3_login_failure(c: connection, is_orig: bool, user: string, password: string) {
	add_record(c);
}

event irc_who_line(c: connection, is_orig: bool, target_nick: string, channel: string, user: string, host: string, server: string, nick: string, params: string, hops: count, real_name: string) {
	add_record(c);
}

event irc_whois_message(c: connection, is_orig: bool, server: string, users: string) {
	add_record(c);
}

event irc_whois_user_line(c: connection, is_orig: bool, nick: string, user: string, host: string, real_name: string) {
	add_record(c);
}

event irc_oper_message(c: connection, is_orig: bool, user: string, password: string) {
	add_record(c);
}

event irc_kick_message(c: connection, is_orig: bool, prefix: string, chans: string, users: string, comment: string) {
	add_record(c);
}

event irc_names_info(c: connection, is_orig: bool, c_type: string, channel: string, users: string_set) {
	add_record(c);
}

event ftp_request(c: connection, command: string, arg: string) {
	add_record(c);
	if ("outbound" in command) {
		set_num_outbound_files_increase(c);
	}
}

event conn_weird(name: string, c: connection, addl: string) {
	add_record(c);
	if (name in set("bad_ICMP_checksum", "bad_TCP_checksum", "bad_UDP_checksum")) {
		set_wrong_fragment_increase(c);
	}
}

event conn_weird_addl(name: string, c: connection, addl: string) {
	add_record(c);
}


event zeek_init() {
	Log::create_stream(LOG, [$columns=features, $path="result"]);
}

event zeek_done() {
	for ([startTime, during, src_addr, src_port, dst_addr, dst_port] in conn_to_feature) {
		Log::write(LOG, conn_to_feature[startTime, during, src_addr, src_port, dst_addr, dst_port]);
	}
}