from __future__ import division
import os
import re
import sys
import subprocess
from distutils.spawn import find_executable
from glob import glob
from datetime import datetime
import settings
import xml.etree.ElementTree as ET
import pyshark


class Packet(object):
    def __init__(self, packet_xml):
        self.time = packet_xml.find('timestamp').text
        self.proto = packet_xml.find('proto').text
        self.src_ip = packet_xml.find('src_ip').text
        self.dst_ip = packet_xml.find('dst_ip').text
        self.src_port = packet_xml.find('src_port').text
        self.dst_port = packet_xml.find('dst_port').text
        #print "packet details is " +self.time+self.src_ip+self.proto+self.dst_ip

class RTPStream(Packet):
    def __init__(self, packet_xml):
        super(RTPStream, self).__init__(packet_xml)
        rtp = packet_xml.find('rtp')
        self.seqno = rtp.find('seq_no').text
        self.ssrc = rtp.find('ssrc').text
        self.codec = rtp.find('codec').text
        self.rtp_timestamp = rtp.find('rtp_timestamp').text
        self.ptime = 0

class RTPEvent(Packet):
    def __init__(self, packet_xml):
        super(RTPEvent, self).__init__(packet_xml)
        event_map = { '10' : '*',
                      '11' : '#',
                      '12' : 'A',
                      '13' : 'B',
                      '14' : 'C',
                      '15' : 'D'
                  }
        dtmf_xml = packet_xml.find('rtpevent')
        if int(dtmf_xml.find('rtpevent_id').text) < 10  or int(dtmf_xml.find('rtpevent_id').text) > 15 :
            self.event_id = dtmf_xml.find('rtpevent_id').text
        else:
            self.event_id = event_map[dtmf_xml.find('rtpevent_id').text]
        self.duration = dtmf_xml.find('rtpevent_duration').text
        self.end_of_event = dtmf_xml.find('rtpevent_end_of_event').text


class SIPPacket(Packet):
    def __init__(self, packet_xml):
        super(SIPPacket, self).__init__(packet_xml)
        sip_xml = packet_xml.find('sip')
        self.sip_call_id = sip_xml.find('sip_call_id').text
        self.method = sip_xml.find('sip_cseq_method').text
        self.status_code = sip_xml.find('sip_status_code').text
        self.sip_request = sip_xml.find('sip_request').text
        self.sip_reply_to  = sip_xml.find('sip_reply').text

class DTMF(Packet):
    def __init__(self, first_packet, start_time, end_time, dtmf_duration, valid, event_id):
        self.time = first_packet.time
        self.proto = first_packet.proto
        self.src_ip = first_packet.src_ip
        self.dst_ip = first_packet.dst_ip
        self.src_port = first_packet.src_port
        self.dst_port = first_packet.dst_port
        self.event_type = 'DTMF'
        self.start_time = start_time
        self.event_id = event_id
        self.end_time = end_time
        self.valid = valid


class CallQualityException(Exception):
    def __init__(self, err_no, message, other_details=None):
        print 'Error [%d] : '%(err_no) + message
        sys.exit(1)

class CallQualityAnalyzer(object):
    def __init__(self):
        self.sip_packets = []
        self.rtp_packets = []
        self.rtpevent_packets = []
        self.dtmf_packets = []
        self.rtp_packet_bad_ptime = []
        self.rtp_stream_report = {}
        self.sip_report = {}
        self.dtmf_report = {}
        self.call_report = {}


    def check_requirements(self):
        for package in settings.required_packages:
            found = find_executable(package)
            if not found:
                raise CallQualityException(1, 'Package %s not installed'%package)


    def get_packet_info(self, packet, packet_type):
        if packet_type == 'SIP':
            packet_obj = SIPPacket()
        elif packet_type == 'RTP':
            packet_obj = RTPStream()
        elif packet_type == 'RTPEVENT':
            packet_obj = DTMF()

    def get_dtmf(self):

        packet_number = 0
        end_packets_count = 0
        previous_packet = ''
        if not len(self.rtpevent_packets):
            return

        for packet in self.rtpevent_packets:
            if not packet_number:
                start_packet = packet
                start_time = datetime.utcfromtimestamp(float(packet.time))
                duration = packet.duration
                packet_number += 1
            elif end_packets_count == 2 and packet.end_of_event == '1' :
                ''' End of valid dtmf '''
                duration = packet.duration
                valid = True
                end_time = datetime.utcfromtimestamp(float(packet.time))
                self.dtmf_packets.append(DTMF(start_packet, start_time, end_time, duration, valid, packet.event_id))
                packet_number = 0
                end_packets_count = 0

            elif int(packet.duration) < int(duration) :
                ''' End of invalid dtmf in previous packet '''
                duration = previous_packet.duration
                valid = False
                end_time = datetime.utcfromtimestamp(float(previous_packet.time))
                self.dtmf_packets.append(DTMF(start_packet, start_time, end_time, duration, valid, packet.event_id))
                packet_number = 0
                end_packets_count = 0

            else:
                ''' Middle of dtmf '''
                if packet.end_of_event == '1':
                    end_packets_count += 1
                packet_number += 1
                duration = packet.duration
            previous_packet = packet

        if packet_number :
            ''' End of invalid dtmf in previous packet '''
            duration = previous_packet.duration
            valid = False
            end_time = datetime.utcfromtimestamp(float(previous_packet.time))
            self.dtmf_packets.append(DTMF(start_packet, start_time, end_time, duration, valid, packet.event_id))
            packet_number = 0
            end_packets_count = 0

    def analyze_pcap(self,pcapfile):
        previous_rtp_packet = {}
        current_rtp_packet_number = 0
        expected_ptime = 20
        sample_rate = 8000
        try:
                output = open('packets.xml', 'w')
                output.write('<pcap>\n')
                output.flush()
                cmd1 = ['tshark', '-q', '-r', pcapfile, '-d', 'udp.port==10000-65536,rtp', '-X', 'lua_script:%s'%(settings.lua_script)]
                #print cmd1
                process = subprocess.Popen(cmd1,stdout=output)
                process.communicate()
                output.write('</pcap>')
                cmd2 = 'tshark -r %s -d udp.port==10000-65536,rtp -Y rtp -T fields -e rtp.ssrc|sort -u' % (pcapfile)
                #print cmd2
                subprocess.call(cmd2, shell=True, stdout=open('ssrc.txt', 'w'))
                ssrc_list = [ ssrc[:-1] for ssrc in open('ssrc.txt', 'r').readlines() ]
                output.close()
        except Exception as err:
            raise CallQualityException(8, err.message)

        try:
            tree = ET.parse('packets.xml')
            pcap = tree.getroot()
            for ssrc in ssrc_list:
                previous_rtp_packet[ssrc] = ''
            for packet in pcap.findall('packet'):
                if packet.find('rtp') is not None:
                    current_rtp_packet = RTPStream(packet)
                    if previous_rtp_packet[current_rtp_packet.ssrc] == '' :
                        current_rtp_packet.ptime = expected_ptime
                        current_rtp_packet_number += 1
                    else:
                        current_rtp_packet.ptime = (int(current_rtp_packet.rtp_timestamp) - int(previous_rtp_packet[current_rtp_packet.ssrc].rtp_timestamp)) * 1000 / sample_rate
                        if current_rtp_packet.ptime != 20 and (int(current_rtp_packet.seqno) == (int(previous_rtp_packet[current_rtp_packet.ssrc].seqno) + 1 )):
                            bad_ptime_details = {
                                'ssrc' : current_rtp_packet.ssrc,
                                'seqno': current_rtp_packet.seqno,
                                'ptime': current_rtp_packet.ptime,
                                'time' : current_rtp_packet.time
                            }
                            self.rtp_packet_bad_ptime.append(bad_ptime_details)
                        current_rtp_packet_number += 1
                    previous_rtp_packet[current_rtp_packet.ssrc] = current_rtp_packet
                    self.rtp_packets.append(current_rtp_packet)
                elif packet.find('rtpevent') is not None:
                    self.rtpevent_packets.append(RTPEvent(packet))
        except Exception as err:
            raise CallQualityException(9, err.message)
        #print "i am here"
        self.get_dtmf()
        #print "i am here2"
        try:
            rtp_summary = open('rtp_summary.txt', 'w')
            sip_summary = open('sip_summary.txt', 'w')
            process = subprocess.Popen(['tshark', '-q', '-r', pcapfile, '-z', 'rtp,streams', '-d' ,'udp.port==10000-65536,rtp'], stdout=rtp_summary)
            process.communicate()
            process = subprocess.Popen(['tshark', '-q', '-r', pcapfile, '-z', 'sip,stat'], stdout=sip_summary)
            process.communicate()
        except Exception as err:
            raise CallQualityException(10, err.message)


    def get_audio(self,pcapfile):
        sample_rate = 8000
        bit_depth = 8
        channels = 1
        raw_stats = {}
        min_timestamp = 0
        try:
                rtp_list = []
                cap = pyshark.FileCapture(pcapfile,display_filter='udp',decode_as={'udp.port==10000-65536': 'rtp'})
                self.get_rtp_streams_info()
                #print self.rtp_stream_report
                for rtp in self.rtp_stream_report:

                    raw_audio = open(rtp+'.raw', 'wb')
                    for i in cap:
                     #print i
                        try:
                         rtp = i[3]
                         if rtp.payload:
                            rtp_list.append(rtp.payload.split(":"))
                        except:
                         pass
                    for rtp_packet in rtp_list:
                        packet = " ".join(rtp_packet)
                        #print(packet)
                        audio = bytearray.fromhex(packet)
                        raw_audio.write(audio)
                raw_files = glob('*.raw')
                for raw_file in raw_files:
                    audio_file = '%s'%(raw_file.split('/')[-1][:-3] + 'wav')
                    mp3_audio_file='%s'%(raw_file.split('/')[-1][:-3] + 'mp3')
                    #cmd='sox -r 8k -e a-law  %s -e signed %s'%(raw_file, audio_file)
                    subprocess.call('sox -r 8k -e a-law  %s -e signed %s'%(raw_file, audio_file), shell = True)
                    subprocess.call('sox -t wav %s -t wav -e signed-integer -c 1 -r 8000 - rate | lame -b 16 - %s ' % (audio_file,mp3_audio_file), shell=True)
                    subprocess.call('mv *.wav Wav/',shell=True)
                    subprocess.call('mv *.mp3 Wav/', shell=True)
                    subprocess.call('rm *.raw', shell=True)
        except Exception as err:
            raise CallQualityException(11, err.message)



    def get_rtp_streams_info(self):
        try:
            #ip = '\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}'
            rtp_summary = open('rtp_summary.txt', 'r').readlines()
            for line in rtp_summary:
                try:
                    rtp_stream = re.search('\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}', line)
                    if rtp_stream.group(0):
                        data = line.split()
                        self.rtp_stream_report[data[4] + '_' + data[0] + '_' + data[2] ] = {
                           'src' : data[0],
                           'src_port' : data[1],
                           'dst' : data[2],
                           'dst_port' : data[3],
                           'ssrc' : data[4],
                           'codec' : data[5] + ' ' + data[6] + ' ' + data[7],
                           'total_packets' : data[8],
                           'lost_packets' : data[9] + ' ' + data[10],
                           'max_delta' : data[11],
                           'max_jitter' : data[12],
                           'mean_jitter' : data[13],
                        }
                except:
                    pass
        except Exception as err:
            raise CallQualityException(12, err.message)


    def get_sip_stats(self):
        for packet in self.sip_packets:
            if packet.method == 'BYE' and packet.sip_request != 'nil' :
                self.sip_report[packet.src_ip + '_' + packet.dst_ip] = {
                    'time'   : datetime.utcfromtimestamp(float(packet.time)),
                    'src_ip' : packet.src_ip,
                    'dst_ip' : packet.dst_ip,
                    'method' : packet.method
                }
    
    def get_dtmf_info(self):
        for dtmf in self.dtmf_packets:
            end_time = dtmf.end_time.strftime('%Y-%m-%d-%H-%M-%S')
            self.dtmf_report[dtmf.event_id + '_' + end_time] = {
                'key' : dtmf.event_id,
                'time' : dtmf.end_time,
                'valid' : dtmf.valid,
            }


    def get_call_info(self):
        self.get_rtp_streams_info()
        self.get_sip_stats()
        self.get_dtmf_info()
        self.call_report['rtp_streams'] = self.rtp_stream_report.values()
        self.call_report['sip_bye'] = self.sip_report.values()
        self.call_report['dtmf'] = self.dtmf_report.values()
        self.call_report['rtp_packet_bad_ptime'] = self.rtp_packet_bad_ptime

    def MOSScore(self,reference,degraded,sameplerate):
        try:
            cmd='./PESQ %s %s %s'% (sameplerate,reference,degraded)
            print cmd
            try:
                subprocess.call(cmd, shell=True, stdout=open('pseq.txt', 'w'))
                MOS = [pesq[:-1] for pesq in open('pseq.txt', 'r').readlines()]
                lastline=MOS[-1]
                mossplit=lastline.split('=')
                mosdata=(mossplit[1].strip()).split("	")
                return mosdata[0]
            except:
                pass
        except Exception as err:
            raise CallQualityException(14, err.message)


if __name__ == '__main__':
    try:

        for pcap in sys.argv:
            if 'pcap' in pcap:
                print 'Extrating Media from pcap:',pcap
                call_pcap = pcap
                #call_pcap = 'DTMF_API.pcap'
                obj = CallQualityAnalyzer()
                #print obj.MOSScore('0x76349B6B_52.205.63.210_172.31.18.204.wav','0x76349B6B_52.205.63.210_172.31.18.204.wav','+8000')
                #exit(0)
                print 'Checking all the required packages are installed or not'
                obj.check_requirements()
                print 'All the required packages are installed'
                print 'Analysis of pcap'
                obj.analyze_pcap(call_pcap)
                print 'Converting to .wav and mp3'
                obj.get_audio(call_pcap)
                obj.get_call_info()
                print 'Successfull Converted to .wav and mp3'
        sys.exit(0)
    except CallQualityException, e:
        print e.message
        sys.exit(1)
    except IndexError:
        print sys.argv[0] + " Pcap file name"
        sys.exit(1)
