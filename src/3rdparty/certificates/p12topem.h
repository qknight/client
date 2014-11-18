#ifndef P12TOPEM_H
#define	P12TOPEM_H

/**
 * \file p12topem.h
 * \brief Librairie statique de conversion d'un p12 en pem
 * \author Pierre MOREAU <p.moreau@agim.idshost.fr>
 * \version 1.0.0
 * \date 09 Janvier 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>

using namespace std;

/**
 * \struct resultP12ToPem p12topem.h
 */
struct resultP12ToPem {
    bool ReturnCode;
    int ErrorCode;
    string Commentaire;
    string PrivateKey;
    string Certificate;
};

/**
 * \brief Fonction de renvoit d'un string depuis un BIO SSL
 * \param BIO o PEM_write_BIO_...
 * \return string PEM
 */
string x509ToString(BIO *o);

/**
 * \brief Transforme un P12 en PEM
 * \param string p12File Chemin vers un fichier P12
 * \param string p12Passwd Password du fichier P12
 * \return result (bool ReturnCode, Int ErrorCode, String Commentaire, String PrivateKey, String Certificate)
 */
resultP12ToPem p12ToPem(string p12File, string p12Passwd);

#endif	/* P12TOPEM_H */

