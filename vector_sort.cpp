#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include <errno.h>

#include <fstream>
#include <vector>

using namespace std;

// ./vector_sort inputfile outfile number_of_file_lines

int main(int argc, char* argv[]) {
  string inputfile = argv[1];
  string outputfile = argv[2];
  int length = atoi(argv[3]);
  vector<string> v;

  string str_buf;
  fstream fr, fw;

  fr.open(inputfile, ios::in);
  fw.open(outputfile, ios::out);

  while(!fr.eof()) {
    getline(fr, str_buf);
    v.push_back(str_buf);
  }

  sort(v.begin(), v.end());

  for(int i=0; i<length+1; i++) {
    fw << v[i] << endl;
  }

  fr.close();
  fw.close();

  return 0;
}
