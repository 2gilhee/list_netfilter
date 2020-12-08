#include <iostream>
#include <iomanip>
#include <fstream>
#include <regex>
#include <vector>
#include <algorithm>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bits/stdc++.h>

using namespace std;

void parsingHttp(uint8_t* data, int length);
void getHttpURL(uint8_t* data, int length, char* temp);
static uint32_t checkPacket(nfq_data* tb, int &flag, char* url);
void compareURL(int &flag, char* filename, char* packetURL);
static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data);

void getError(string error) {
	perror(error.c_str());
	exit(1);
}

void printLine() {
	cout << "-----------------------------------------------" << endl;
}

void printByHexData(uint8_t *printArr, int length) {
	for(int i=0; i<length; i++) {
		if(i%16==0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";
	}
	cout << dec << endl;
	printLine();
}

int main(int argc, char *argv[]) {
	struct nfq_handle* handle = nfq_open();

	/*open lib handle*/
	if(!handle)
		getError("error during nfq_open()");

	/*unbinding existing nf_queue handler for AF_INET*/
	if(nfq_unbind_pf(handle,AF_INET) < 0)
		getError("error during nfq_unbind_pf()");

	/*binding nfnetlink_queue as nf_queue handler for AF_INET*/
	if(nfq_bind_pf(handle,AF_INET) < 0)
		getError("error during nfq_bind_pf()");

	/*binding this socket to queue '0'*/
	struct nfq_q_handle* qhandle = nfq_create_queue(handle, 0, &callback, argv[1]); //you can give user defined parameter at last parameter. (e.g., nfq_create_queue(handle,0,&callback,&userClass);)
	if(!qhandle)
		getError("error during nfq_create_queue()");

	/*setting copy_packet mode*/

	if(nfq_set_mode(qhandle, NFQNL_COPY_PACKET, 0xffff) < 0)
		getError("can't set packet_copy mode");

	int fd = nfq_fd(handle);
	int rv=0;
	char buf[4096] __attribute__ ((aligned));


	while (true) {
		if((rv=recv(fd,buf,sizeof(buf),0))>=0) //if recv success
			nfq_handle_packet(handle,buf,rv); //call callback method
	}
	return 0;
}

void parsingHttp(uint8_t* data, int length) {
  char temp[length] = {0,};
  for(int i=0; i<length; i++) {
    if(data[i]==0x0d && data[i+1]==0x0a) { // \r\n
      sprintf(temp, "%s%c", temp, data[i]);
      i++;
    } else {
      sprintf(temp, "%s%c", temp, data[i]);
    }
  }
  sprintf(temp, "%s%x", temp, 0x00);
  cout << temp << endl;
}

int parsingHttpLine(uint8_t* data, int length) {
  int i;
  for(i=0; i <length; i++) {
    if(data[i]==0x0d && data[i+1]==0x0a)
      break;
  }
  return i+2; // return the size of line
}

void getHttpURL(uint8_t* data, int length, char* packetURL) {
  // parsing the http packet and find the URL ("Host: ")
  int num = parsingHttpLine(data, length);
  data += num;

  sprintf(packetURL, "%c", data[0]);
  for(int i=1; i<length-num; i++) {
    if(data[i]==0x0d && data[i+1]==0x0a)
      break;
    else
      sprintf(packetURL, "%s%c", packetURL, data[i]);
  }
}

static uint32_t checkPacket(nfq_data* tb, int &flag, char* filename) {
  int id, protocol, hook = 0;
  struct nfqnl_msg_packet_hdr *ph;

  ph = nfq_get_msg_packet_hdr(tb);
  if(ph) {
    id = ntohl(ph->packet_id);
    protocol = ntohl(ph->hw_protocol);
    hook = ph->hook;
  }

  uint8_t* data;
  int ret = nfq_get_payload(tb, &data);
  if(ret <= 0) { // no ip packet
    return id;
  }

  // defalut = NF_ACCEPT
  flag = NF_ACCEPT;

  // packet header
  struct ip* ipHeader;
  struct tcphdr* tcpHeader;

  ipHeader = (struct ip*)data;
  int ipHeaderLength = ipHeader->ip_hl * 4;

  if(ipHeader->ip_p == IPPROTO_TCP) { // check if it is tcp header
    data += ipHeaderLength;
    tcpHeader = (struct tcphdr*)data;
    int tcpHeaderLength = tcpHeader->doff * 4;
    int destPort = htons(tcpHeader->dest);

    if(destPort == 0x0050) { // http port: 80(0x0050)
      data += tcpHeaderLength;

      if((ret-ipHeaderLength-tcpHeaderLength) > 0) {
        // Editing: Need to fetch packet URL and compareURL
        char packetURL[4096] __attribute__ ((aligned));
        getHttpURL(data, ret-ipHeaderLength-tcpHeaderLength, packetURL);

        cout << "!!!!!! FLAG: " << flag << " !!!!!!" << endl;
        cout << "checkPacket's packetURL: " << packetURL << endl;
        compareURL(flag, filename, packetURL);

        cout << "AFTER compareURL: " << flag << endl;

        printLine();
        cout << endl;
      }
    }
  }

  return id;
}

void compareURL(int &flag, char* filename, char* packetURL) {
  string str_buf;
  fstream fs;
  vector<string> v;

  fs.open(filename, ios::in);
  while(!fs.eof()) {
    getline(fs, str_buf);
    str_buf = "Host: www." + str_buf;
    v.push_back(str_buf);
  }
  fs.close();

  auto iter = find(v.begin(), v.end(), packetURL);
  if(iter != v.end()) {
    cout << "compareURL's iter: " << *iter << endl;
    flag = NF_DROP;
  }
}

static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data) {
  (void)nfmsg;
  int flag = 0;

  uint32_t id = checkPacket(nfa, flag, (char*)data); // call another method

  return nfq_set_verdict(qhandle, id, flag, 0, NULL);
}
