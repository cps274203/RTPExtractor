-- SIP Call Parser

do

    local timestamp_f = Field.new("frame.time_epoch")
    local udp_src_port_f = Field.new("udp.srcport")
    local udp_dst_port_f = Field.new("udp.dstport")
    local tcp_src_port_f = Field.new("tcp.srcport")
    local tcp_dst_port_f = Field.new("tcp.dstport")
    local src_ip_f = Field.new("ip.src")
    local dst_ip_f = Field.new("ip.dst")
    local ip_proto_f = Field.new("ip.proto")
        
    -- SIP fields
    local sip_callid_f = Field.new("sip.Call-ID")
    local sip_cseq_method_f = Field.new("sip.CSeq.method")
    local sip_request_line_f = Field.new("sip.Request-Line")
    local sip_status_code_f = Field.new("sip.Status-Code")
    local sip_reply_to_f = Field.new("sip.Reply-To")
    local sip_msg_body_f = Field.new("sip.msg_body")

    -- RTP Fields 
    local rtp_seq_f = Field.new("rtp.seq")
    local rtp_payload_type_f = Field.new("rtp.p_type")
    local rtp_timestamp_f = Field.new("rtp.timestamp")
    local rtp_ssrc_f = Field.new("rtp.ssrc")

    -- RTP Event Fields
    local rtp_event_id_f = Field.new("rtpevent.event_id")
    local rtp_event_end_of_event_f = Field.new("rtpevent.end_of_event")
    local rtp_event_duration_f = Field.new("rtpevent.duration")

    local proto = { ["6"] = "TCP", ["17"] = "UDP" }

    local function sip_listener()
    
        local tap = Listener.new("ip", "(sip and (sip.CSeq.method != REGISTER) and (sip.CSeq.method != OPTIONS))")

        function tap.packet(pinfo,tvb,ip)
           local timestamp, src_ip, dst_ip, sip_cseq_method, sip_status_code, sip_callid, sip_request_line, sip_reply_to, sip_msg_body = timestamp_f(), src_ip_f(), dst_ip_f(), sip_cseq_method_f(), sip_status_code_f(), sip_callid_f(), sip_request_line_f(), sip_reply_to_f(), sip_msg_body_f()

           local src_port = udp_src_port_f()
           local dst_port = udp_dst_port_f()
           local proto = "UDP"
           if not src_port then
               src_port = tcp_src_port_f()
               dst_port = tcp_dst_port_f()
               proto = "TCP"
            end

            print("<packet>")
            print("<timestamp>"..tostring(timestamp).."</timestamp>")
            print("<proto>"..tostring(proto).."</proto>")
            print("<src_ip>"..tostring(src_ip).."</src_ip>")
            print("<src_port>"..tostring(src_port).."</src_port>")
            print("<dst_ip>"..tostring(dst_ip).."</dst_ip>")
            print("<dst_port>"..tostring(dst_port).."</dst_port>")
            print("<sip>")
            print("    <sip_call_id>"..tostring(sip_callid).."</sip_call_id>")
            print("    <sip_cseq_method>"..tostring(sip_cseq_method).."</sip_cseq_method>")
            print("    <sip_status_code>"..tostring(sip_status_code).."</sip_status_code>")
            print("    <sip_request>"..tostring(sip_request_line).."</sip_request>")
            print("    <sip_reply>"..tostring(sip_reply_to).."</sip_reply>")
            print("</sip>")
            print("</packet>")
	    print()
        end
    end

    local function rtp_listener()
       
        local tap = Listener.new("ip","rtp and not rtpevent")

        function tap.packet(pinfo, tvb, rtp,ip)
            local src_ip,dst_ip,timestamp,rtp_seq,rtp_payload_type, rtp_timestamp, src_port, dst_port,proto_id = src_ip_f(),dst_ip_f(),timestamp_f(),rtp_seq_f(),rtp_payload_type_f(), rtp_timestamp_f(), udp_src_port_f(), udp_dst_port_f(), ip_proto_f()
	    local proto = proto
	    local ssrc = rtp_ssrc_f()
            local codec = { ["0"] = "g711u", ["8"] = "g711a", ["18"] = "g729", ["99"] = "g729ab" };
            print("<packet>")
            print("<timestamp>"..tostring(timestamp).."</timestamp>")
            print("<proto>"..proto[tostring(proto_id)].."</proto>")
            print("<src_ip>"..tostring(src_ip).."</src_ip>")
            print("<src_port>"..tostring(src_port).."</src_port>")
            print("<dst_ip>"..tostring(dst_ip).."</dst_ip>")
            print("<dst_port>"..tostring(dst_port).."</dst_port>")
            print("<rtp>")
            print("    <seq_no>"..tostring(rtp_seq).."</seq_no>")
            print("    <ssrc>"..tostring(ssrc).."</ssrc>")
            print("    <codec>"..codec[tostring(rtp_payload_type)].."</codec>")
	    print("    <rtp_timestamp>"..tostring(rtp_timestamp).."</rtp_timestamp>")
	    print("</rtp>")
	    print("</packet>")
	    print()
        end
    end

    local function rtpevent_listener()

        local tap = Listener.new("ip","rtpevent")

        function tap.packet(pinfo, tvb, rtpevent)
            local timestamp = timestamp_f()
            local src_ip = src_ip_f()
            local dst_ip = dst_ip_f()
            local src_port = udp_src_port_f()
            local dst_port = udp_dst_port_f()
            local rtp_event_id = rtp_event_id_f()
            local rtp_event_duration = rtp_event_duration_f()
            local rtp_event_end_of_event = rtp_event_end_of_event_f()
	    local proto_id = ip_proto_f()
            local proto = proto

            print("<packet>")
            print("<timestamp>"..tostring(timestamp).."</timestamp>")
            print("<proto>"..proto[tostring(proto_id)].."</proto>")
            print("<src_ip>"..tostring(src_ip).."</src_ip>")
            print("<src_port>"..tostring(src_port).."</src_port>")
            print("<dst_ip>"..tostring(dst_ip).."</dst_ip>")
            print("<dst_port>"..tostring(dst_port).."</dst_port>")
	    print("<rtpevent>")
            print("    <rtpevent_id>"..tostring(rtp_event_id).."</rtpevent_id>")
            print("    <rtpevent_duration>"..tostring(rtp_event_duration).."</rtpevent_duration>")
            print("    <rtpevent_end_of_event>"..tostring(rtp_event_end_of_event).."</rtpevent_end_of_event>")
	    print("</rtpevent>")
	    print("</packet>")
	    print()
        end
    end            
            
    sip_listener()
    rtp_listener()
    rtpevent_listener()

end
