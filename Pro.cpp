#include <vector>
#include <fstream>
#include <string>
#include <filesystem>
#include <iostream>
#include <regex>

using namespace std;
namespace filesys = filesystem;

#include "keccak.h"

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif


/// same as reset()
Keccak::Keccak(Bits bits)
: m_blockSize(200 - 2 * (bits / 8)),
  m_bits(bits)
{
  reset();
}


/// restart
void Keccak::reset()
{
  for (size_t i = 0; i < StateSize; i++)
    m_hash[i] = 0;

  m_numBytes   = 0;
  m_bufferSize = 0;
}


/// constants and local helper functions
namespace
{
  const unsigned int KeccakRounds = 24;
  const uint64_t XorMasks[KeccakRounds] =
  {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
  };

  /// rotate left and wrap around to the right
  inline uint64_t rotateLeft(uint64_t x, uint8_t numBits)
  {
    return (x << numBits) | (x >> (64 - numBits));
  }

  /// convert litte vs big endian
  inline uint64_t swap(uint64_t x)
  {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#endif
#ifdef _MSC_VER
    return _byteswap_uint64(x);
#endif

    return  (x >> 56) |
           ((x >> 40) & 0x000000000000FF00ULL) |
           ((x >> 24) & 0x0000000000FF0000ULL) |
           ((x >>  8) & 0x00000000FF000000ULL) |
           ((x <<  8) & 0x000000FF00000000ULL) |
           ((x << 24) & 0x0000FF0000000000ULL) |
           ((x << 40) & 0x00FF000000000000ULL) |
            (x << 56);
  }


  /// return x % 5 for 0 <= x <= 9
  unsigned int mod5(unsigned int x)
  {
    if (x < 5)
      return x;

    return x - 5;
  }
}


/// process a full block
void Keccak::processBlock(const void* data)
{
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
#define LITTLEENDIAN(x) swap(x)
#else
#define LITTLEENDIAN(x) (x)
#endif

  const uint64_t* data64 = (const uint64_t*) data;
  // mix data into state
  for (unsigned int i = 0; i < m_blockSize / 8; i++)
    m_hash[i] ^= LITTLEENDIAN(data64[i]);

  // re-compute state
  for (unsigned int round = 0; round < KeccakRounds; round++)
  {
    // Theta
    uint64_t coefficients[5];
    for (unsigned int i = 0; i < 5; i++)
      coefficients[i] = m_hash[i] ^ m_hash[i + 5] ^ m_hash[i + 10] ^ m_hash[i + 15] ^ m_hash[i + 20];

    for (unsigned int i = 0; i < 5; i++)
    {
      uint64_t one = coefficients[mod5(i + 4)] ^ rotateLeft(coefficients[mod5(i + 1)], 1);
      m_hash[i     ] ^= one;
      m_hash[i +  5] ^= one;
      m_hash[i + 10] ^= one;
      m_hash[i + 15] ^= one;
      m_hash[i + 20] ^= one;
    }

    // temporary
    uint64_t one;

    // Rho Pi
    uint64_t last = m_hash[1];
    one = m_hash[10]; m_hash[10] = rotateLeft(last,  1); last = one;
    one = m_hash[ 7]; m_hash[ 7] = rotateLeft(last,  3); last = one;
    one = m_hash[11]; m_hash[11] = rotateLeft(last,  6); last = one;
    one = m_hash[17]; m_hash[17] = rotateLeft(last, 10); last = one;
    one = m_hash[18]; m_hash[18] = rotateLeft(last, 15); last = one;
    one = m_hash[ 3]; m_hash[ 3] = rotateLeft(last, 21); last = one;
    one = m_hash[ 5]; m_hash[ 5] = rotateLeft(last, 28); last = one;
    one = m_hash[16]; m_hash[16] = rotateLeft(last, 36); last = one;
    one = m_hash[ 8]; m_hash[ 8] = rotateLeft(last, 45); last = one;
    one = m_hash[21]; m_hash[21] = rotateLeft(last, 55); last = one;
    one = m_hash[24]; m_hash[24] = rotateLeft(last,  2); last = one;
    one = m_hash[ 4]; m_hash[ 4] = rotateLeft(last, 14); last = one;
    one = m_hash[15]; m_hash[15] = rotateLeft(last, 27); last = one;
    one = m_hash[23]; m_hash[23] = rotateLeft(last, 41); last = one;
    one = m_hash[19]; m_hash[19] = rotateLeft(last, 56); last = one;
    one = m_hash[13]; m_hash[13] = rotateLeft(last,  8); last = one;
    one = m_hash[12]; m_hash[12] = rotateLeft(last, 25); last = one;
    one = m_hash[ 2]; m_hash[ 2] = rotateLeft(last, 43); last = one;
    one = m_hash[20]; m_hash[20] = rotateLeft(last, 62); last = one;
    one = m_hash[14]; m_hash[14] = rotateLeft(last, 18); last = one;
    one = m_hash[22]; m_hash[22] = rotateLeft(last, 39); last = one;
    one = m_hash[ 9]; m_hash[ 9] = rotateLeft(last, 61); last = one;
    one = m_hash[ 6]; m_hash[ 6] = rotateLeft(last, 20); last = one;
                      m_hash[ 1] = rotateLeft(last, 44);

    // Chi
    for (unsigned int j = 0; j < StateSize; j += 5)
    {
      // temporaries
      uint64_t one = m_hash[j];
      uint64_t two = m_hash[j + 1];

      m_hash[j]     ^= m_hash[j + 2] & ~two;
      m_hash[j + 1] ^= m_hash[j + 3] & ~m_hash[j + 2];
      m_hash[j + 2] ^= m_hash[j + 4] & ~m_hash[j + 3];
      m_hash[j + 3] ^=      one      & ~m_hash[j + 4];
      m_hash[j + 4] ^=      two      & ~one;
    }

    // Iota
    m_hash[0] ^= XorMasks[round];
  }
}


/// add arbitrary number of bytes
void Keccak::add(const void* data, size_t numBytes)
{
  const uint8_t* current = (const uint8_t*) data;

  if (m_bufferSize > 0)
  {
    while (numBytes > 0 && m_bufferSize < m_blockSize)
    {
      m_buffer[m_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (m_bufferSize == m_blockSize)
  {
    processBlock((void*)m_buffer);
    m_numBytes  += m_blockSize;
    m_bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= m_blockSize)
  {
    processBlock(current);
    current    += m_blockSize;
    m_numBytes += m_blockSize;
    numBytes   -= m_blockSize;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    m_buffer[m_bufferSize++] = *current++;
    numBytes--;
  }
}


/// process everything left in the internal buffer
void Keccak::processBuffer()
{
  unsigned int blockSize = 200 - 2 * (m_bits / 8);

  // add padding
  size_t offset = m_bufferSize;
  // add a "1" byte
  m_buffer[offset++] = 1;
  // fill with zeros
  while (offset < blockSize)
    m_buffer[offset++] = 0;

  // and add a single set bit
  m_buffer[blockSize - 1] |= 0x80;

  processBlock(m_buffer);
}


/// return latest hash as 16 hex characters
std::string Keccak::getHash()
{
  // save hash state
  uint64_t oldHash[StateSize];
  for (unsigned int i = 0; i < StateSize; i++)
    oldHash[i] = m_hash[i];

  // process remaining bytes
  processBuffer();

  // convert hash to string
  static const char dec2hex[16 + 1] = "0123456789abcdef";

  // number of significant elements in hash (uint64_t)
  unsigned int hashLength = m_bits / 64;

  std::string result;
  for (unsigned int i = 0; i < hashLength; i++)
    for (unsigned int j = 0; j < 8; j++) // 64 bits => 8 bytes
    {
      // convert a byte to hex
      unsigned char oneByte = (unsigned char) (m_hash[i] >> (8 * j));
      result += dec2hex[oneByte >> 4];
      result += dec2hex[oneByte & 15];
    }

  // Keccak224's last entry in m_hash provides only 32 bits instead of 64 bits
  unsigned int remainder = m_bits - hashLength * 64;
  unsigned int processed = 0;
  while (processed < remainder)
  {
    // convert a byte to hex
    unsigned char oneByte = (unsigned char) (m_hash[hashLength] >> processed);
    result += dec2hex[oneByte >> 4];
    result += dec2hex[oneByte & 15];

    processed += 8;
  }

  // restore state
  for (unsigned int i = 0; i < StateSize; i++)
    m_hash[i] = oldHash[i];

  return result;
}


/// compute Keccak hash of a memory block
std::string Keccak::operator()(const void* data, size_t numBytes)
{
  reset();
  add(data, numBytes);
  return getHash();
}


/// compute Keccak hash of a string, excluding final zero
std::string Keccak::operator()(const std::string& text)
{
  reset();
  add(text.c_str(), text.size());
  return getHash();
}


struct node {
    string hash;
    int row;
    int column;
    node * left = NULL;
    node * right = NULL;
    node(string h){
        hash = h;
    }
};

struct file{
    string path;
    string name;
    int size;

};

struct file_reader{
    vector<file *> files;
    string directory;

    file_reader(string dir){
        directory = dir;
    }

    void read_files(){

        std::string directory_path;
        double file_size;
    
        for ( filesystem::recursive_directory_iterator end, dir(this->directory); dir != end; dir++ ) {

            //excludes only these types of files are counted.
            regex reg = regex("(\\.cpp|\\.h)");
            

            directory_path = dir->path().string();

            bool is_file = regex_search(directory_path, reg);

            if(is_file){

                filesys::path pathObj(directory_path);
                
                files.push_back(new file());

                files.back()->size = filesys::file_size(pathObj);
                files.back()->path = directory_path;
                files.back()->name = pathObj.filename();
                
            }
        }

        }
    void sort_files(){
       q_sort(1, this->files.size()-1);
    }

    vector<node*> hash_files(){

        string hash;
        vector<file*> f = this->files;
        vector<node *> leaves;
        Keccak keccak;
        vector<char> file;
    
        char c;

        for(int i = 0; i < f.size(); i++){
            
            std::ifstream in_file(f[i]->path, std::ifstream::binary);
            file.clear();
            while(!in_file.eof())
            {
                in_file >> c;
                file.push_back(c);
            }
    
    
        std::string bin_file_rep(file.begin(), file.end()-1);
            
        hash = keccak(bin_file_rep);

        leaves.push_back(new node(hash));
        leaves.back()->column = i + 1;
        leaves.back()->row = 1;

        in_file.close();

        }  

        return leaves;      

    }

    void q_sort(int start, int end)
    {
        // base case
        if (start >= end)
            return;
    
        // partitioning the array
        int p = partition(start, end);
    
        // Sorting the left part
        q_sort(start, p - 1);
    
        // Sorting the right part
        q_sort(p + 1, end);
    }

    int partition( int start, int end)
    {
        string pivot = this->files.at(start)->name;

        int count = 0;
        for(int i = start + 1; i <= end; i++)
        {
            if(this->files.at(i)->name <= pivot){
                count++;
            }
        }
        
        int pivot_index = start + count;
        std::swap(this->files.at(start), this->files.at(pivot_index));

        int i = start, j = end;
    
        while (i < pivot_index && j > pivot_index) {
    
            while (this->files[i]->name <= pivot) {
                i++;
            }
    
            while (this->files[j]->name > pivot) {
                j--;
            }
            if (i < pivot_index && j > pivot_index) {
                std::swap(this->files[i++], this->files[j--]);
            }
        }
    
        return pivot_index;
    }

};

struct tree{

    node * root;
    vector <node *> children;
    Keccak keccak;
    
    

    tree(vector <node *> n){
      children = n;
    }
    void build_tree(){

      vector <node *> parents;
      int row = 1;
      int displacement = 0;
      int size = 0;
      string temp, parent_hash;
      while(this->children.size() != 1){
        row++;
        size = this->children.size();
        displacement = this->children.size()%2;
        temp.clear();
        parents.clear();

        for(int i = 0; i < this->children.size() - displacement; i+=2){
          for(int j = i; j < i + 2; j++ ){
            temp = temp + this->children[j]->hash;
          }
          parent_hash = keccak(temp);
          parents.push_back(new node(parent_hash));
          parents.back()->column = parents.size();
          parents.back()->row = row;
          parents.back()->left = this->children[i];
          parents.back()->right = this->children[i+1];
          temp.clear();

          
          }
          //if there is one left over hash it with itself
          if(displacement){
            temp = this->children[size - displacement]->hash + this->children[size - displacement]->hash;
            parent_hash = keccak(temp);
            parents.push_back(new node(parent_hash));
            parents.back()->column = parents.size();
            parents.back()->row = row;
            parents.back()->left = this->children[size-displacement];
            parents.back()->right = this->children[size-displacement];
          }

         
         this->children = parents;

        }
        root = this->children[0];

      }
    
    void verify_root(string ID, string hash){

      smatch index;
      smatch h;
      string buf;
      string first_file;
      ifstream in("result.csv");
      vector<string> hashes;
      
      

      while(!in.eof()){
        getline(in, buf);
       /* if (regex_search(buf, h, regex("1,2,[0-9a-z]*"))){
          string shash = h[0];
          shash = shash.substr(4,shash.length());
          first_file = shash;
          
        }
*/
        if(regex_search(buf, h, regex(",2,[0-9a-z]*"))){
            string shash = h[0];
            shash = shash.substr(3,shash.length());
            hashes.push_back(shash);

          }

        
        

      }

      string next = keccak(keccak(ID) + hashes[0]);

      for(int i = 1; i < hashes.size(); i++){
        string temp = hashes[i];
        next = keccak(next + temp);
      }

      if(next == hash){
        cout << "Match" << endl;

      }
      else{
        cout << "No Match" << endl;
      }
    }
    void update_tree(){

    }
    void print_tree(node * root, ofstream &out){
      
     
      if(root->left == NULL || root->right == NULL){
       
        out << root->row << "," << root->column << ","<< root->hash << endl;
      }
      else{
        out << root->row << "," << root->column << ","<< root->hash << endl;
        print_tree(root->left, out);
        print_tree(root->right, out);
      }
      
    }
};

void add_Id(std::vector<file*> &f, string s){
    f.push_back(new file());
    f.back()->path = s;
    f.back()->name = s;
}
   
int main(int argc, char* argv[])
{
    file_reader  f = file_reader(argv[1]);
    add_Id(f.files, argv[2]);
    f.read_files();
    f.sort_files();
    ofstream out("result.csv");
    vector<node*> leaves = f.hash_files();
    tree version(leaves);
    version.build_tree();
    version.print_tree(version.root, out);
    version.verify_root("d161f2301a6bcba459ca903c70e767895ccd4715ba228824410e2145293667a9","f157161c5dddcf4759e88eb020e4e91da1634a8e5ec936aa690f73cd65c715ad");
    out.close();

    }


