##! Bro script is used to detect suspicious activity over SMB protocol

@load base/frameworks/files
@load base/frameworks/notice
@load base/utils/addrs
# @load policy/protocols/smb

module SMBSuspectActivity;

export {  
    ## Custom defined alerts
    redef enum Notice::Type += {  
        Admin_Share_Suspicious_UNC,
        Admin_Share_Wannacry_Beacon,
        SMB1_Transaction2_Reserved_Cmd_Usage
    };

    ## Define networks that we don't normally see on this campus (at at least see through east-west links)
    const rfc_1918_subnets: set[subnet] = {
        192.168.0.0/16,
        172.16.0.0/8
    } &redef;

    # https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html
    # https://logrhythm.com/blog/using-netmon-to-detect-wannacry-initial-exploit-traffic/
    const wannacry_beacons: set[addr] = {
        192.168.56.20,
        172.16.99.5  
    } &redef;
}

event smb2_tree_connect_request(c : connection, hdr : SMB2::Header, path : string)
{
    # Most UNC paths will be expressed as \\192.168.20.20\IPC$.
    # We split on this and grab the IP portion of the string
    
    local unc_ip_vec: vector of string = split_string(path, /\\/);
    local unc_ip: string;

    # Sometimes the path wont contain an IP, but just contain IPC$ for example. 
    # Immediately return since this detection won't work
    if(|unc_ip_vec| == 1 || path == "IPC$" || path == "ADMIN$" || path == "C$") {
        return;
    }
    unc_ip = unc_ip_vec[2];

    # Does the IP string match an IPv4 check?
    if (unc_ip == ipv4_addr_regex) 
    {
        # Convert to addr type and check to see if the destination IP is different than the UNC request.
        # Also check if the extracted UNC IP is part of a suspected network
        local unc_ip_addr = to_addr(unc_ip);

        if(c$id$resp_h != unc_ip_addr && unc_ip_addr in rfc_1918_subnets && unc_ip_addr !in wannacry_beacons &&
            ("IPC$" in path || "ADMIN$" in path || "C$" in path))
        {
            # print fmt("Found mismatch: %s:%s -> %s:%s : %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, path);
            NOTICE([$note=Admin_Share_Suspicious_UNC,
                $msg=fmt("Potentially malicious use of an administrative share with UNC and/or IP mismtach"), 
                $sub=fmt("%s",path), 
                $conn=c]);
        }
    }
}

event smb1_tree_connect_andx_request(c : connection, hdr : SMB1::Header, path : string, service : string)
{
    # Most UNC paths will be expressed as \\192.168.20.20\IPC$.
    # We split on this and grab the IP portion of the string
    local unc_ip_vec: vector of string = split_string(path, /\\/);
    local unc_ip: string;

    # Sometimes the path wont contain an IP, but just contain IPC$ for example. 
    # Immediately return since this detection won't work
    if(|unc_ip_vec| == 1 || path == "IPC$" || path == "ADMIN$" || path == "C$") {
        return;
    }
    unc_ip = unc_ip_vec[2];

    # Does the IP string match an IPv4 check?
    if (unc_ip == ipv4_addr_regex) 
    {
        # Convert to addr type and check to see if the destination IP is different than the UNC request.
        # Also check if the extracted UNC IP is part of a suspected network
        local unc_ip_addr = to_addr(unc_ip);

        if(c$id$resp_h != unc_ip_addr && unc_ip_addr in rfc_1918_subnets && unc_ip_addr !in wannacry_beacons &&
            ("IPC$" in path || "ADMIN$" in path || "C$" in path))
        {
            # print fmt("Found mismatch: %s:%s -> %s:%s : %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, path);
            NOTICE([$note=Admin_Share_Suspicious_UNC,
                $msg=fmt("Potentially malicious use of an administrative share with UNC and/or IP mismtach"), 
                $sub=fmt("%s",path), 
                $conn=c]);
        }

        if(unc_ip_addr in wannacry_beacons && ("IPC$" in path || "ADMIN$" in path || "C$" in path))
        {
            NOTICE([$note=Admin_Share_Wannacry_Beacon,
                $msg=fmt("Potentially malicious use of administrative share involving suspected Wannacry/Doublepulsar beacon"), 
                $sub=fmt("%s",path), 
                $conn=c]);
        }
    }
}

event smb1_transaction2_request(c: connection, hdr: SMB1::Header, args: SMB1::Trans2_Args, sub_cmd: count)
{
    # https://cloudblogs.microsoft.com/microsoftsecure/2017/06/30/exploring-the-crypt-analysis-of-the-wannacrypt-ransomware-smb-exploit-propagation/
    # The second-stage shellcode implants DoublePulsar by patching the SMB1 Transaction2 dispatch table. 
    # It overwrites one of the reserved command handlers for the SESSION_SETUP (0xe) subcommand of the Transaction2 request. 
    # This subcommand is reserved and not commonly used in regular code.
    # Check for Wannacry, ExternalBlue, DoublePulsar etc.

    # print fmt("%s - %s ---- %s", c$smb_state$current_cmd$command, c$smb_state$current_cmd$sub_command, c);

    if(/^SESSION_SETUP$/ in c$smb_state$current_cmd$sub_command)
    {
        # We have decided not to suppress this alert in the notice framework to monitor attacks.
        # TODO: Suggestion here is to use the SumStats framework
        NOTICE([$note=SMB1_Transaction2_Reserved_Cmd_Usage,
            $msg=fmt("Potentially malicious use of SMB1 Transaction2 reserved command detected"), 
            $sub=fmt("%s|%s", c$smb_state$current_cmd$command, c$smb_state$current_cmd$sub_command), 
            $conn=c]);
    } 
}

