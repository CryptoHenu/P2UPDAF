#include "ccamain.h"
#include <stdio.h>
#include <iostream>
#include <string.h>
#include "pbc.h"
#include "cpastruct.h"
#include "cpakeygen.h"
#include "cpadec.h"
#include "cpaenc.h"
#include "cpamaptozr.h"
#include "ccamain.h"
#include "ccastruct.h"
#include "ccakeygen.h"
#include "ccadec.h"
#include "ccaenc.h"
#include "ccamap.h"
#include "ccamain.h"

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

    // CCA scheme test
    int ccatest;
    ccatest = ccamain();
    if (ccatest){
        cout << "CCA scheme test is successful !" << endl;
    }
    else{
        cout << "CCA scheme test is false !" << endl;
    }

    return 0;

}