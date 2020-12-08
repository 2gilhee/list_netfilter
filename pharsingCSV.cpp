#include <iostream>
#include <iomanip>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <stdio.h>
#include <fstream>
#include <regex>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <bits/stdc++.h>

using namespace std;

int main(int argc, char *argv[]) {
  string str_buf;
  fstream fs;

  fs.open(argv[1], ios::in);

  regex re("^[a-zA-Z0-9-~!@#$%^&*()_+=`{}[\\]:;<>,.?\\/]+\\.com$");

  while(!fs.eof()) {
    getline(fs, str_buf);
    int i = regex_match(str_buf, re);
    cout << str_buf << ": " << i << endl;
  }
  fs.close();

  return 0;
}
