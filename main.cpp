#include "ccamain.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include <stdint.h>
#include <iostream>

using namespace std;

int main(){

    int ccatest;
    ccatest = ccamain();
    if(ccatest) {
        cout <<  "CCA test is successfull !"     << endl;
    }
    else{
        cout <<  "CCA test is false !"     << endl;
    }

    return 1;

}