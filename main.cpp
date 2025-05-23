#include "ccamain.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
<<<<<<< HEAD

#include "pbc.h"
#include "cpastruct.h"
#include "cpakeygen.h"
#include "cpadec.h"
#include "cpaenc.h"
#include "cpamaptozr.h"
#include "cpamain.h"

using namespace std;



int main()
{
    // CPA scheme test
    int cpatest;
    cpatest = cpamain();
    if (cpatest){
        cout << "CPA scheme test is successful !" << endl;
    }
    else{
        cout << "CPA scheme test is false !" << endl;
    }


    return 0;
=======
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

>>>>>>> CCA
}