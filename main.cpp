/*jun wang, 08/21/2018*/

#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <sstream>
#include <ctime>
#include <iomanip>


#include "seal.h"

using namespace std;
using namespace seal;

void print_example_banner(string title);
void cryptonets();

int main()
{
    cryptonets();
    return 0;
}

void cryptonets()
{

    /*
     * I use random values as the model weights, this method does not compromise the efficiency analysis.
     * If you want to use read model paramters, simply load your weights to their corresponding variables.
    */

    print_example_banner("CryptoNets. structure description: minionn, https://eprint.iacr.org/2017/452.pdf, p13, Figure 11.");
    
    EncryptionParameters parms;
    parms.set_poly_modulus("1x^4096 + 1");
    parms.set_coeff_modulus(ChooserEvaluator::default_parameter_options().at(4096));
    parms.set_plain_modulus(101285036033); //101285036033 //1099511922689
    parms.validate();

    IntegerEncoder encoder(parms.plain_modulus());

    cout << "Generating keys ..." << endl;
    KeyGenerator generator(parms);
    generator.generate();
    cout << "... key generation complete" << endl;
    Ciphertext public_key = generator.public_key();
    Plaintext secret_key = generator.secret_key();

    
    Encryptor encryptor(parms, public_key);
    Evaluator evaluator(parms);
    Decryptor decryptor(parms, secret_key);
    auto time_norelin_start = chrono::high_resolution_clock::now();

    cout << "Generating pseudo-weights for Conv 1 ..." << endl;
    int p_len = 5*25;
    vector<Plaintext> p_conv_vec;
    for (int idx=0; idx<p_len; idx++)
    {
        Plaintext enc_rval  = encoder.encode((rand() % 10)+1);
        p_conv_vec.emplace_back(enc_rval); 
    }

    int c_len = 169*25;
    vector<Ciphertext> c_conv_vec;
    for (int idx=0; idx<c_len; idx++)
    {
        Plaintext enc_rval  = encoder.encode((rand() % 5)+1);
        Ciphertext prval = encryptor.encrypt(enc_rval);
        c_conv_vec.emplace_back(prval);
    }

    cout << "...pseudo-weights for Conv 1 complete" << endl;

    //conv 1: 5X169 <- 5X25 * 25X169, convert conv to matrix multiplication
    cout << "Calculating Conv 1 ..." << endl;
    int dot_len = 25;
    vector<Ciphertext> conv_out;
    for (int i=0; i<p_len; i+=dot_len)
    {
        for (int j=0; j<c_len; j+=dot_len)
        {
            vector<Ciphertext> dots;
            for(int x=0; x<dot_len; x++)
            {
                Ciphertext c_tpm = evaluator.multiply_plain(c_conv_vec[j+x], p_conv_vec[i+x]);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum = evaluator.add_many(dots);
            conv_out.emplace_back(dotsum); 
        }
    }

    p_conv_vec.clear();
    c_conv_vec.clear();

    //act: square
    cout << "...Conv 1 is done" << endl;

    cout << "Calculating activation layer 1 (square)..." << endl;
    vector<Ciphertext> act_out;
    for (vector<Ciphertext>::iterator it = conv_out.begin() ; it != conv_out.end(); ++it)
    {
        Ciphertext c_tpm = evaluator.square(*it);
        act_out.emplace_back(c_tpm);
    }

    conv_out.clear();
    cout << "...Activation layer 1 is done" << endl;

    //mean_pool: 100X1 <- 100X845 * 845X1, convert pool to matrix multiplication
    //!!!I remove pool layer here, as the mean pool is in fact a CONV operation.
    //!!!To evalute the accuracy performance, you should add this mean pooling layer

    cout << "Calculating pool + linear..." << endl;

    //Generating pseudo-weights
    p_len = 100*845;
    vector<Plaintext> p_pool_vec;
    for (int idx=0; idx<p_len; idx++)
    {
        Plaintext enc_rval  = encoder.encode((rand() % 7)+1);
        p_pool_vec.emplace_back(enc_rval); 
    }
    // pseudo-weights complete

    dot_len = 845; 
    c_len = 845*1; // act_out.size()
    vector<Ciphertext> pool_out;
    for (int i=0; i<p_len; i+=dot_len)
    {
        for (int j=0; j<c_len; j+=dot_len)
        {
            vector<Ciphertext> dots;
            for(int x=0; x<dot_len; x++)
            { 
                //cout << j+x<<"  "<<i+x << endl;
                Ciphertext c_tpm = evaluator.multiply_plain(act_out[j+x], p_pool_vec[i+x]);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum = evaluator.add_many(dots);
            pool_out.emplace_back(dotsum);
        }
    }
    act_out.clear();
    p_pool_vec.clear();

    cout << "...Pool+Linear layer  is done" << endl;

    //act 2

    cout << "Calculating activation layer 2 (square)..." << endl;
    vector<Ciphertext> act_out_2;
    for (vector<Ciphertext>::iterator it = pool_out.begin() ; it != pool_out.end(); ++it)
    {
        Ciphertext c_tpm = evaluator.square(*it);
        act_out_2.emplace_back(c_tpm);
    }

    pool_out.clear();
    cout << "...Activation layer 2 is done" << endl;


    //FC: 10X1<- 10X100 * 100X1
    cout << "Calculating FC layer..." << endl;

    //Generating pseudo-weights
    p_len = 10*100;
    vector<Plaintext> p_fc_vec;
    for (int idx=0; idx<p_len; idx++)
    {
        Plaintext enc_rval  = encoder.encode((rand() % 9)+1);
        p_fc_vec.emplace_back(enc_rval); 
    }
    // pseudo-weights complete

    dot_len = 100; 
    c_len = 100*1; // act_out_2.size()
    vector<Ciphertext> fc_out;
    for (int i=0; i<p_len; i+=dot_len)
    {
        for (int j=0; j<c_len; j+=dot_len)
        {
            vector<Ciphertext> dots;
            for(int x=0; x<dot_len; x++)
            {
                Ciphertext c_tpm = evaluator.multiply_plain(act_out_2[j+x], p_fc_vec[i+x]);
                dots.emplace_back(c_tpm);
            }
            Ciphertext dotsum = evaluator.add_many(dots);
            fc_out.emplace_back(dotsum);
        }
    }

    cout << "...FC layer  is done" << endl;

    //add decrypts here... if you want

    auto time_norelin_end = chrono::high_resolution_clock::now();
    cout << "Time of CryptoNets: " << chrono::duration_cast<chrono::microseconds>(time_norelin_end - time_norelin_start).count()/(1000*1000.0)
        << " seconds" << endl;
    return;

}


void print_example_banner(string title)
{
    if (!title.empty())
    {
        size_t title_length = title.length();
        size_t banner_length = title_length + 2 + 2 * 10;
        string banner_top(banner_length, '*');
        string banner_middle = string(10, '*') + " " + title + " " + string(10, '*');

        cout << endl
            << banner_top << endl
            << banner_middle << endl
            << banner_top << endl
            << endl;
    }
}
