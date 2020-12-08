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

// ./vector_find file item_to_search

int main(int argc, char* argv[]) {
  string file = argv[1];
  string item = argv[2];
  vector<string> v;

  string str_buf;
  fstream fs;

  fs.open(file, ios::in);

  while(!fs.eof()) {
    getline(fs, str_buf);
    v.push_back(str_buf);
  }

  auto iter = find(v.begin(), v.end(), item);

  if(iter != v.end())
    cout << *iter << endl;
  else
    cout << "NOT FOUND" << endl;

  fs.close();

  return 0;
}
