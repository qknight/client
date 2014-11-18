/**
 * \file p12topem.cpp
 * \brief Librairie statique de conversion d'un p12 en pem
 * \author Pierre MOREAU <p.moreau@agim.idshost.fr>
 * \version 1.0.0
 * \date 09 Janvier 2014
 */

#include "p12topem.h"

using namespace std;

/**
 * \fn string x509ToString (BIO)
 * \brief Fonction de renvoit d'un string depuis un BIO SSL
 * \param BIO o PEM_write_BIO_...
 * \return string PEM
 */
string x509ToString(BIO *o) {
    int len = 0;
    BUF_MEM *bptr;
    void* data;
    string ret = "";
    
    BIO_get_mem_ptr(o, &bptr);
    len = bptr->length;
    data = calloc(len+10, sizeof(char));
    BIO_read(o, data, len);
    ret = strdup((char*)data);
    free(data);
        
    return ret;
}

/**
 * \fn resultP12ToPem p12ToPem (string, string)
 * \brief Transforme un P12 en PEM
 * \param string p12File Chemin vers un fichier P12
 * \param string p12Passwd Password du fichier P12
 * \return result (bool ReturnCode, Int ErrorCode, String Commentaire, String PrivateKey, String Certificate)
 */
resultP12ToPem p12ToPem(string p12File, string p12Passwd) {
    FILE *fp;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;
    
    BIO *o = BIO_new(BIO_s_mem());
    
    string privateKey = "";
    string certificate = "";
        
    resultP12ToPem ret;
    ret.ReturnCode = false;
    ret.ErrorCode = 0;
    ret.Commentaire = "";
    ret.PrivateKey = "";
    ret.Certificate = "";
    
    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    if(!(fp = fopen(p12File.c_str(), "rb"))) {
        ret.ErrorCode = 1;
        ret.Commentaire = strerror(errno);
        return ret;
    }
    
    p12 = d2i_PKCS12_fp(fp, &p12);
    fclose (fp);
    
    if (!p12) {
        ret.ErrorCode = 2;
        ret.Commentaire = "Impossible d'ouvrir le fichier PKCS#12";
        return ret;
    }
    if (!PKCS12_parse(p12, p12Passwd.c_str(), &pkey, &cert, &ca)) {
        ret.ErrorCode = 3;
        ret.Commentaire = "Impossible de parser le fichier PKCS#12 (mauvais mot de passe ?)";
        return ret;
    }
    PKCS12_free(p12);
    
    if (!(pkey && cert)) {
        ret.ErrorCode = 4;
        ret.Commentaire = "Le certificat et/ou la clef n'existent pas";
    } else {
        PEM_write_bio_PrivateKey(o, pkey, 0, 0, 0, NULL, 0);
        privateKey = x509ToString(o);
                
        PEM_write_bio_X509(o, cert);
        certificate = x509ToString(o);
        
        BIO_free(o);
        
        ret.ReturnCode = true;
        ret.ErrorCode = 0;
        ret.Commentaire = "Tout est OK!";
        ret.PrivateKey = privateKey;
        ret.Certificate = certificate;
    }
    return ret;
}
