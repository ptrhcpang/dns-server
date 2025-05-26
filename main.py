import socket
import sys

class dns_message:

    def __init__(self, 
                msgid = 1234, 
                qr = 0,
                opcode = 0, 
                rd = 0,
                rcode = 0,
                name = [b"\x0danydomainname\x03com\x00"],
                ans_class = [1],
                ans_ttl = [60],
                ans_data = [b"\x7f\x00\x00\x03"]):
        
        self.msgid = msgid
        self.qr = qr
        self.opcode = opcode
        self.rd = rd
        self.rcode = rcode
        self.name = name
        self.aclass = ans_class
        self.attl = ans_ttl
        self.ip = ans_data

        self.questioncount = 0
        self.answercount = 0

    def header(self,
        headerid = 1234,
        headerqr = 0,
        headeropcd = 0,
        headeraa = 0,
        headertc = 0,
        headerrd = 0,
        headerra = 0,
        headerz = 0,
        headerrcd = 0,
        headerqdct = 0,
        headeranct = 0,
        headernsct = 0,
        headerarct = 0):

        header_bin = headerqr
        header_bin = (header_bin << 4) + headeropcd
        header_bin = (header_bin << 1) + headeraa
        header_bin = (header_bin << 1) + headertc
        header_bin = (header_bin << 1) + headerrd
        header_bin = (header_bin << 1) + headerra
        header_bin = (header_bin << 3) + headerz
        header_bin = (header_bin << 4) + headerrcd
        header_bin = (header_bin << 16) + headerqdct
        header_bin = (header_bin << 16) + headeranct
        header_bin = (header_bin << 16) + headernsct
        header_bin = (header_bin << 16) + headerarct

        headerid = bytes([headerid >> 8]) + bytes([headerid%256])
        headerbody = b""
        for i in range(10):
            mask = 0b11111111 << (9 - i)*8
            a = (header_bin & mask) >> (9 - i)*8
            headerbody = headerbody + bytes([a])


        # Packet Identifier (ID) 	        16 bits/ 2nd byte
        # Query/Response Indicator (QR) 	1 bit 
        # Operation Code (OPCODE) 	        4 bits 
        # Authoritative Answer (AA) 	    1 bit 
        # Truncation (TC) 	                1 bit 
        # Recursion Desired (RD) 	        1 bit/ 3rd byte
        # Recursion Available (RA) 	        1 bit 
        # Reserved (Z) 	                    3 bits 
        # Response Code (RCODE) 	        4 bits/ 4th byte
        # Question Count (QDCOUNT) 	        16 bits/ 6th byte
        # Answer Record Count (ANCOUNT) 	16 bits/ 8th byte
        # Authority Record Count (NSCOUNT) 	16 bits/ 10th byte
        # Additional Record Count (ARCOUNT) 16 bits/ 12th byte

        return headerid + headerbody

    # private as the function modifies the self.questioncount variable
    # question format:
    #   label sequence of variable length, ending in \x0.
    #   2 byte type
    #   2 byte class
    def __question(self, 
                name = b"\x0danydomainname\x03com\x00", 
                qtypev = 1, 
                qclassv = 1):
        
        #increase question count every time question() is called
        self.questioncount += 1
        
        qname = name
        qtype = bytes([qtypev >> 8]) + bytes([qtypev%256])
        qclass =  bytes([qclassv >> 8]) + bytes([qclassv%256])
        
        return qname + qtype + qclass
    
    # private as the function modifies the self.answercount variable 
    # answer format:
    #   label sequence of variable length, ending in \x0.
    #   2 byte type
    #   2 byte class   
    #   4 byte time-to-live
    #   2 byte data length  (here 4)
    #   data of data length (here an IP4 address)
    def __answer(self, 
                name = b"\x0danydomainname\x03com\x00",
                atypev = 1, 
                aclassv = 1, 
                attlv = 60, 
                adata = b"\x7f\x00\x00\x03"):
        
        #increase answer count every time answer() is called
        self.answercount += 1
        
        aname = name
        atype =   bytes([atypev >> 8]) + bytes([atypev%256])
        aclass =  bytes([aclassv >> 8]) + bytes([aclassv%256])
        attl = b""
        for i in range(4):
            mask = 0b11111111 << (3 - i)*8
            a = (attlv & mask) >> (3 - i)*8
            attl = attl + bytes([a])
        adatalen = len(adata)
        alen = bytes([adatalen >> 8]) + bytes([adatalen%256])

        return aname + atype + aclass + attl + alen + adata
    
    def __authority(self):
        # to be built
        pass
    
    def __addition(self):
        #to be built
        pass

    def i_compression(self):
        pass

    def fullmsg(self):
        questions = b""
        answers = b""
        
        for i, name in enumerate(self.name):
            questions = questions + self.__question(name = name)
            
            # if qr == 1 (response), construct answers
            if(self.qr == 1):
                answers = answers + self.__answer(name = name, 
                                                    aclassv = self.aclass[i],
                                                    attlv = self.attl[i],
                                                    adata = self.ip[i])

        fmsg = self.header(headerid = self.msgid,
                            headerqr = self.qr,
                            headeropcd = self.opcode,
                            headerrd = self.rd,
                            headerrcd = self.rcode,
                            headerqdct = self.questioncount, 
                            headeranct = self.answercount)
        fmsg = fmsg + questions + answers
        
        self.questioncount = 0
        self.answercount = 0

        return fmsg


def parse_header(buf):

    msgid = int.from_bytes(buf[:2], byteorder='big')
    opcodev = buf[2]
    rd = opcodev%2
    opcode = (opcodev>>3)%16
    # rcode = 4
    rcode = buf[3] & 0b00001111
    # if(opcode == 0):
    #     rcode = 0
    
    return msgid, opcode, rd, rcode


# Accepts entire DNS messgage, 
# a starting byte offset which has to
# be the beginning of a NAME section 
# of a QUESTION, ANSWER, AUTHORITY, 
# or ADDITIONAL section. 
# Also accepts a flag indicating whether 
# we want the returned name decompressed.
# Returns the NAME and the new offset value
# that is the starting byte _after_ the 
# NAME label sequence

def labelseq_parser(buf,start, decompFlag = True):
    
    if(not decompFlag):
        print(buf)
    
    stepper = start
    namebuf = b""
    noughtflag = 1 # flag = 1 if last label 
                    # in label seqeuence is 
                    # actually a label, and 
                    # flag = 0 if it is a pointer

    while(buf[stepper]!= 0):

        # pointers start with 0b11xxxxxx = 192 + 0bxxxxxx
        # pointers are always at the end of label sequence 
        if(buf[stepper] >= 192):
            
            # if forwarding, we decompress names 
            # (in order to send questions to resolver one by one)
            if(decompFlag):
                # read the offset to which the pointer is pointing
                offset = int.from_bytes(buf[stepper:stepper + 2], byteorder='big')&0x3fff
                
                while(buf[offset]!= 0):
                    # copy full label sequence at offset/address 
                    # to which pointer is pointing
                    namebuf = namebuf + bytes([buf[offset]])
                    offset = offset + 1
                    
                namebuf = namebuf + bytes([0])

            else: # pointers are 2 bytes long
                namebuf = namebuf + buf[stepper:stepper + 2]
            
            # advance stepper on buf by 1 
            # so that it is at the end of 
            # the pointer (2 bytes in total)
            stepper = stepper + 1
            noughtflag = 0
            break
        
        # otherwise step through the next word of the label sequence
        nextlen = buf[stepper]
        # print(f"buffer length is {len(buf)}; the stepper value is {stepper}, and nextlen is {nextlen}")
        if(stepper + nextlen > len(buf)):
            raise ValueError("Label length exceeds buffer size.")

        namebuf = namebuf + buf[stepper:stepper + nextlen + 1]
        
        stepper = stepper + nextlen + 1
        noughtflag = 1
        
    # exiting the while loop puts stepper on \x00 that ends a label sequence 
    # or on the last byte of a pointer
    # if ending label is not pointer, copy the 
    # terminal \x00 byte into the name buffer as well
    if(noughtflag == 1):
        namebuf = namebuf + buf[stepper:stepper + 1]
    
    # puts the stepper on the byte directly 
    # after the NAME section of either questions or answers
    stepper = stepper + 1

    return stepper, namebuf



def parse_questions(buf, decompFlag):

    name = []
    namebuf = b""

    stepper = 12
    questioncount = int.from_bytes(buf[4:6], byteorder='big')

    for i in range(questioncount):
        stepper, namebuf = labelseq_parser(buf,stepper,decompFlag)
        # each question is a variable-length NAME label sequence
        # followed by four bytes
        stepper = stepper + 4
        
        #append newly parsed name to name list and clear buffer
        name.append(namebuf)
        namebuf = b""
    
    return stepper, name


def parse_answers(buf, qlength):
    
    answercount = int.from_bytes(buf[6:8], byteorder='big')    
    if(answercount == 0):
        raise ValueError("No answer in response.")
    
    # qlength is the number of bytes up to 
    # the last byte of the questions section
    # therefore buf[qlength] is the start of 
    # the new (ANSWERS) section
    stepper = qlength
 

    # step over/extract label sequence
    stepper, _ = labelseq_parser(buf,stepper,False)
    
    # 2 bytes for type
    ans_type = int.from_bytes(buf[stepper:stepper + 2], byteorder='big')
    stepper += 2
    
    # 2 bytes for class
    ans_class = int.from_bytes(buf[stepper:stepper + 2], byteorder='big')
    stepper += 2

    # 4 bytes for ttl
    ans_ttl = int.from_bytes(buf[stepper:stepper + 4], byteorder='big')
    stepper += 4

    # 2 bytes for data length
    ans_datalen = int.from_bytes(buf[stepper:stepper + 2], byteorder='big')
    stepper += 2

    # variable bytes for data
    if(stepper + ans_datalen > len(buf)):
        raise ValueError("Data length exceeds buffer size.")

    ans_data = buf[stepper:stepper + ans_datalen]

    return ans_type, ans_class, ans_ttl, ans_data


def main():
    
    BUFFER_SIZE = 8192
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    
    # can try using ArgumentParser from the argparse package
    if(sys.argv[1] == "--resolver"):
       
        # decompress label sequences of questions
        # if forwarding to resolver
        decompFlag = True

        try:
            
            res_ip = sys.argv[2].split(':')[0]
            res_port = int(sys.argv[2].split(':')[1])

        except Exception as e:

            print(f"Error handling <ip>:<port> information: {e}")


    else:
        decompFlag = False
    


    while True:
        try:
            buf, source = udp_socket.recvfrom(BUFFER_SIZE)
            opcodeflip = 0 
            msgid, opcode, rd, rcode = parse_header(buf)
            
            # suppress inverse query/server status request
            # and responds to client with rcode = 4, i.e., 
            # server does not implement request
            opcodeflip = opcode
            opcode = 0

            print("incoming message:")
            _, compressedname = parse_questions(buf, False)
                
            
            if(not decompFlag):

                # query database here and create auth message

                # stand-in 
                aipv = []
                for i, _ in enumerate(compressedname):
                    aipv.append(b"\x7f\x00\x00\x03")
                
                # construct response
                response = dns_message(msgid = msgid, 
                                        opcode = opcode, 
                                        rd = rd, 
                                        rcode = rcode,
                                        name = compressedname,
                                        ans_data = aipv).fullmsg()
                
                # send reponse
                udp_socket.sendto(response, source)

            else:
                
                _, namelist = parse_questions(buf, True)
                
                res_resp_buf = b""

                # res_resp = []
                anstype = []
                ansclass = []
                ansttl = []
                ansdata = []
                
                # open resolver socket
                res_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                res_sock.settimeout(1)

                # forward and receive all messages
                # for _, name in enumerate(namelist):
                for i, name in enumerate(namelist):
                    forward = dns_message(msgid = msgid, 
                                        qr = 0,#remove answers
                                        opcode = opcode, 
                                        rd = rd, 
                                        rcode = rcode,
                                        name = [name]
                                        ).fullmsg()
                    print(f"forward message number {i} is:\n {forward}")

                    try:
                        # send question to resolver
                        res_sock.sendto(forward, (res_ip, res_port))
                        # receive response from resolver
                        res_resp_buf, source2 = res_sock.recvfrom(BUFFER_SIZE)

                    except socket.timeout:
                        print(f"Timeout waiting for response for question {name}")

                    # extract answer class, ttl, data from resolver response 
                    print("response from resolver:")
                    qlength, _ = parse_questions(res_resp_buf,False)
                    ans_type, ans_class, ans_ttl, ans_data = parse_answers(res_resp_buf,qlength)
                    anstype.append(ans_type)
                    ansclass.append(ans_class)
                    ansttl.append(ans_ttl)
                    ansdata.append(ans_data)
                    
                    # clear buffer
                    res_resp_buf = b""
                
                # assemble response
                
                # server does not implement request
                if (opcodeflip != 0):
                    opcode = opcodeflip
                    rcode = 4
                
                response = dns_message(msgid = msgid, 
                                        qr = 1,
                                        opcode = opcode,
                                        rd = rd,
                                        rcode = rcode,
                                        name = compressedname,
                                        ans_class = ansclass,
                                        ans_ttl = ansttl,
                                        ans_data = ansdata).fullmsg()
                
                # close resolver socker
                res_sock.close()

                # reply to query
                print(f"response to client:\n {response}")
                udp_socket.sendto(response, source)
                
                    
            
        except Exception as e:

            print(f"Error receiving data: {e}")
            break




if __name__ == "__main__":
    main()
    
