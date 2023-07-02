#include<bits/stdc++.h>
using namespace std;

std::string calculateSHA256(const std::string& input) {
    const unsigned int BLOCK_SIZE = 64;
    const unsigned int HASH_SIZE = 32;
    const unsigned int K[] = { /* Constants for SHA-256 */
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Initialize hash values (constants)
    unsigned int H[HASH_SIZE] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // Pre-processing
    std::string paddedMessage;
    uint64_t messageLength = input.length() * 8;

    paddedMessage = input + '\x80'; // Append 1 bit followed by zeros
    while ((paddedMessage.length() * 8) % BLOCK_SIZE != (BLOCK_SIZE - 8))
        paddedMessage += '\x00'; // Pad with zeros

    // Append the message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; --i) {
        paddedMessage += static_cast<char>((messageLength >> (8 * i)) & 0xFF);
    }

    // Process the message in successive 512-bit chunks
    for (unsigned int i = 0; i < paddedMessage.length(); i += BLOCK_SIZE) {
        std::vector<unsigned int> words(64, 0);

        // Break chunk into sixteen 32-bit big-endian words
        for (unsigned int j = 0; j < 16; ++j) {
            for (int k = 3; k >= 0; --k) {
                words[j] |= static_cast<unsigned char>(paddedMessage[i + j * 4 + (3 - k)]) << (k * 8);
            }
        }

        // Extend the sixteen 32-bit words into sixty-four 32-bit words
        for (unsigned int j = 16; j < 64; ++j) {
            unsigned int s0 = (words[j - 15] >> 7) | (words[j - 15] << 25);
            unsigned int s1 = (words[j - 15] >> 18) | (words[j - 15] << 14);
            unsigned int s2 = (words[j - 15] >> 3) ^ (words[j - 15] << 29);
            unsigned int s3 = (words[j - 2] >> 17) | (words[j - 2] << 15);
            unsigned int s4 = (words[j - 2] >> 19) | (words[j - 2] << 13);
            unsigned int s5 = (words[j - 2] >> 10) ^ (words[j - 2] << 22);

            words[j] = words[j - 16] + s0 + words[j - 7] + s1 + s2 + s3 + s4 + s5;
        }

        // Initialize working variables to the current hash value
        unsigned int a = H[0];
        unsigned int b = H[1];
        unsigned int c = H[2];
        unsigned int d = H[3];
        unsigned int e = H[4];
        unsigned int f = H[5];
        unsigned int g = H[6];
        unsigned int h = H[7];

        // Compression function main loop
        for (unsigned int j = 0; j < 64; ++j) {
            unsigned int s0 = (a >> 2) | (a << 30);
            unsigned int s1 = (a >> 13) | (a << 19);
            unsigned int s2 = (a >> 22) | (a << 10);
            unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
            unsigned int t2 = s0 + s1 + s2 + maj;

            unsigned int s3 = (e >> 6) | (e << 26);
            unsigned int s4 = (e >> 11) | (e << 21);
            unsigned int s5 = (e >> 25) | (e << 7);
            unsigned int ch = (e & f) ^ (~e & g);
            unsigned int t1 = h + s3 + ch + K[j] + words[j];

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add the compressed chunk to the current hash value
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // Produce the final hash value (big-endian)
    std::stringstream ss;
    for (unsigned int i = 0; i < HASH_SIZE; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (H[i] >> 24);
        ss << std::hex << std::setw(2) << std::setfill('0') << ((H[i] >> 16) & 0xFF);
        ss << std::hex << std::setw(2) << std::setfill('0') << ((H[i] >> 8) & 0xFF);
        ss << std::hex << std::setw(2) << std::setfill('0') << (H[i] & 0xFF);
    }

    return ss.str();
}
std::pair<int, std::vector<int>> abstractString(std::string input_string) {
    // Remove spaces from the beginning and end of the string
    size_t start = input_string.find_first_not_of(' ');
    size_t end = input_string.find_last_not_of(' ');
    input_string = input_string.substr(start, end - start + 1);

    // Extract words and integers from the string
    std::vector<int> integers;
    std::istringstream iss(input_string);
    std::string word;
    while (iss >> word) {
        try {
            int num = std::stoi(word);
            integers.push_back(num);
        } catch (const std::exception& e) {
            // Ignore non-integer words
        }
    }

    // Determine the value of x based on keywords
    int x = -1;
    if (input_string.find("add") != std::string::npos && input_string.find("minor") != std::string::npos) {
        x = 0;
    } else if (input_string.find("add") != std::string::npos) {
        x = 1;
    } else if (input_string.find("send") != std::string::npos) {
        x = 2;
    }

    return std::make_pair(x, integers);
}

vector<string>mempool;
int reward;
void configure(string s);
class block{
    public:
    string hash;
    string prevHash;
    map<int,int>changes;
    int proofOfWork;
    long long int timeStamp;
};


string calHash(block newBlock){
    string str;
    str+=newBlock.prevHash;
    str+=to_string(newBlock.proofOfWork);
    for(auto t:newBlock.changes){
        int a=t.first;
        int b=t.second;
        str+=to_string(a);
        str+=to_string(b);
    }
    str+=to_string(newBlock.timeStamp);
    return calculateSHA256(str);
}

class isMiner{
    public:
int id;
vector<block> blockchain;
void mine();
};

vector<isMiner> ourMiners;

void equateTo(isMiner & faulty,isMiner &notFaulty){
    int id1=faulty.id;
    faulty=notFaulty;
    faulty.id=id1;
}


bool hashFault(isMiner miner){
     if(miner.blockchain.size()==0) return false;
     for(auto t:miner.blockchain){
         if(calHash(t)!=t.hash) return true;
     }
     return false;
}

void checkAll(){
    vector<isMiner>faulty;
    vector<isMiner>notFaulty;
    for(int i=0;i<ourMiners.size();i++) if(hashFault(ourMiners[i])) faulty.push_back(ourMiners[i]);
    else notFaulty.push_back(ourMiners[i]);
    for(int i=0;i<faulty.size();i++){
      if(notFaulty.size()>0)  equateTo(faulty[i],notFaulty[0]);
    }
}

bool verifyTrans(block newBlock){
     bool flag=true;
    for(auto t:ourMiners) if(calHash(newBlock)!=newBlock.hash) flag= false;
    return flag;
}
    

void updateAll(block newBlock){
    for(auto &t:ourMiners){
        t.blockchain.push_back(newBlock);
    }
}

void addMiner(int id){
    for(auto t:ourMiners){
        if(t.id==id) {cout<<"cant add "<<id<<" as miner as already that id is taken"; return;}
    }
    isMiner newMiner;
    for(auto t:ourMiners) if(!hashFault(t)){
        newMiner=t;
        break;
    }
    newMiner.id=id;
}

void isMiner::mine() {
    checkAll();
    map<int,int>currData;
    for(int i=0;i<2;i++){
        string str=mempool[i];
        pair<int,vector<int>>p=abstractString(str);
        int type=p.first;
        if(type==0) addMiner(p.second[0]);
        else if(type==1) currData[p.second[0]]=0;
        else if(type==2){
            int cost=p.second[0];
            int from=p.second[1];
            int to=p.second[2];
            int has=0;
            for(auto blocks:blockchain){
                map<int,int>mp=blocks.changes;
                if(mp.find(from)==mp.end()) continue;
                has+=mp[from];
            }
            if(currData.find(from)!=currData.end()) has+=currData[from];
            if(this->blockchain.size()==0) has =1e5;
            if(has<cost or cost==0) {
                cout<<"send "<< cost<<" from "<< from<< " to "<<to <<" account failed "<<endl;
                 
                 
            }  
            else{
                if(has!=1e5) currData[from]-=cost;
                currData[to]+=cost;
                cout<<"send "<< cost<<" from "<< from<< " to "<<to <<" account succeed "<<endl;
            }
                
        }
        else cout<<"Please provide valid inputs"<<endl;
    }
    currData[this->id]+=reward;    
    block newBlock;
    newBlock.proofOfWork=this->id;
    newBlock.changes=currData;
    newBlock.timeStamp=time(nullptr);
    if(blockchain.size()==0) newBlock.prevHash="0000000000000000000000000000000000000000000000000000000000000000";
    else newBlock.prevHash=this->blockchain.back().hash;
    newBlock.hash=calHash(newBlock);
    if(verifyTrans(newBlock))  mempool.clear();
    else configure("");
    updateAll(newBlock);        
}
    






void init(int sizee){
    for(int i=0;i<sizee;i++){
        isMiner newMiner;
        newMiner.id=i;
        ourMiners.push_back(newMiner);
    }
}
void configure(string s){
    if(s.size()>0) mempool.push_back(s);
    if(mempool.size()<2) return;
    unsigned seed = static_cast<unsigned>(std::time(0));
    std::mt19937 rng(seed);
    if(ourMiners.size()<1) {cout<<"NO miners"<<endl;return;}
    std::uniform_int_distribution<int> dist(0,ourMiners.size()-1);
    int randomNumber = dist(rng);
    ourMiners[randomNumber].mine();
}

    //statements allowed
//add x as miner
//add x as a normal node
// send a from x to y account (sends a amount from x to y if possible else prints invalid )
int main(){
    cout<<"How many miners you want to add: "<<endl;
    int miners;
    cin>>miners;
    init(miners);
    cout<<"what will be the minor reward: "<<endl;
    cin>>reward;
    bool flag=true;
    while(flag and miners){
        cin>>flag;
        string s;
        cin>>s;
        configure(s);
    }
    cout<<"blockchain stopped successfully"<<endl;
}