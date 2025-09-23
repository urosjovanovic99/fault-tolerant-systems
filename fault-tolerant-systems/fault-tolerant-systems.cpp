//#include <iostream>
#include "node.h"

int main()
{
    // Assume mynode has a keypair (issued_key = private key)
    std::string msg = "Hello OpenSSL";
    node mynode = node("A", 0);

    // Sign with private key
    auto sig = mynode.sign_message(msg);
    // Verify with public key
    bool ok = mynode.verify_message(msg, sig);

    if (ok) {
        std::cout << "Signature verified\n";
    }
    else {
        std::cout << "Signature failed\n";
    }

}
