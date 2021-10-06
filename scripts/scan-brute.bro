##! Bro script is used to detect suspicious activity over SMB protocol

@load base/frameworks/files
@load base/frameworks/notice
@load base/utils/addrs
# @load policy/protocols/smb

module SMBSuspectActivity;

export {  
    ## Custom defined alerts
    redef enum Notice::Type += {  
        Address_Scan_Access_Denied,
        Address_Scan_Logon_Failure,
        Logon_Brute_Force
    };

    ## The threshold of SMB access denied attempts for alerting
    const smb_address_scan_access_denied_threshold: double = 20.0 &redef;

    ## The threshold of SMB access denied attempts for alerting
    const smb_address_scan_logon_failure_threshold: double = 20.0 &redef;
    
    ## The number of hosts to sample when collecting summary statistics
    const total_samples: count = 5 &redef;

    ## Scan timing interval
    const scan_timing: interval = 5min &redef;
}

event smb1_error(c: connection, hdr: SMB1::Header, is_orig:  bool)
{
    # Field existence check before we proceed processing
    if(! c?$smb_state) return;
    if(! c$smb_state?$current_cmd) return;
    if(! c$smb_state$current_cmd?$command) return;
    if(! c$smb_state$current_cmd?$status) return;

    local smb_cmd = c$smb_state$current_cmd;
    # print(c$smb_state);
    # print fmt("DEBUG: %s -> %s (%s - %s)", c$id$orig_h, c$id$resp_h,c$smb_state$current_cmd$command, c$smb_state$current_cmd$status);

    if((smb_cmd$command == "SESSION_SETUP_ANDX" || smb_cmd$command == "TRANSACTION") && smb_cmd$status == "ACCESS_DENIED") {
        SumStats::observe("smb.session_setup_andx.access_denied", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
        return;
    }

    if(smb_cmd$command == "SESSION_SETUP_ANDX" && smb_cmd$status == "LOGON_FAILURE") {
        SumStats::observe("smb.session_setup_andx.logon_failure", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
        return;
    }
    
}

event bro_init()
{
    local r1 = SumStats::Reducer($stream="smb.session_setup_andx.access_denied", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE), $num_samples=total_samples);
    SumStats::create([$name="smb.session_setup_andx.access_denied.unique",
                $epoch=scan_timing,
                $reducers=set(r1),
                $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                    # We must always return a double here
                    return result["smb.session_setup_andx.access_denied"]$unique+0.0;
                },
                $threshold=smb_address_scan_access_denied_threshold, # This must be a double, not an integer
                $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                    local r = result["smb.session_setup_andx.access_denied"];
                    local dur = duration_to_mins_secs(r$end-r$begin);
                    local message = fmt("%s was seen across %d unique hosts with SMB ACCESS_DENIED rejections in %s", key$host, r$unique, dur);
                    local sub_msg = fmt("Sampled targets: ");
                    local samples = r$samples;
                    for ( i in samples ) {
                        if ( samples[i]?$str )
                            sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
                    }
                    NOTICE([$note=Address_Scan_Access_Denied,
                            $msg=message, 
                            $sub=sub_msg,
                            $src=key$host,
                            $identifier=cat(key$host)]);
                }]);

    local r2 = SumStats::Reducer($stream="smb.session_setup_andx.logon_failure", $apply=set(SumStats::UNIQUE, SumStats::SAMPLE), $num_samples=total_samples);
    SumStats::create([$name="smb.session_setup_andx.logon_failure.unique",
                $epoch=scan_timing,
                $reducers=set(r2),
                $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                    # We must always return a double here
                    return result["smb.session_setup_andx.logon_failure"]$unique+0.0;
                },
                $threshold=smb_address_scan_logon_failure_threshold, # This must be a double, not an integer
                $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                    local r = result["smb.session_setup_andx.logon_failure"];
                    local dur = duration_to_mins_secs(r$end-r$begin);
                    local message = fmt("%s was seen across %d unique hosts with SMB LOGON_FAILURE rejections in %s", key$host, r$unique, dur);
                    local sub_msg = fmt("Sampled targets: ");
                    local samples = r$samples;
                    for ( i in samples ) {
                        if ( samples[i]?$str )
                            sub_msg = fmt("%s%s %s", sub_msg, i==0 ? "":",", samples[i]$str);
                    }
                    NOTICE([$note=Address_Scan_Logon_Failure,
                            $msg=message, 
                            $sub=sub_msg,
                            $src=key$host,
                            $identifier=cat(key$host)]);
                }]);
}
