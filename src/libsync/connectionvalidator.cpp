/*
 * Copyright (C) by Klaas Freitag <freitag@owncloud.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include <QtCore>
#include <QNetworkReply>

#include "connectionvalidator.h"
#include "theme.h"
#include "account.h"
#include "networkjobs.h"
#include <creds/abstractcredentials.h>
#include "../3rdparty/certificates/p12topem.h"

using namespace QKeychain;

namespace OCC {

ConnectionValidator::ConnectionValidator(AccountPtr account, QObject *parent)
    : QObject(parent),
      _account(account),
      _isCheckingServerAndAuth(false)
{
  qDebug() << __FUNCTION__;
}

QString ConnectionValidator::statusString( Status stat )
{
    switch( stat ) {
    case Undefined:
        return QLatin1String("Undefined");
    case Connected:
        return QLatin1String("Connected");
    case NotConfigured:
        return QLatin1String("NotConfigured");
    case ServerVersionMismatch:
        return QLatin1String("Server Version Mismatch");
    case CredentialsWrong:
        return QLatin1String("Credentials Wrong");
    case StatusNotFound:
        return QLatin1String("Status not found");
    case UserCanceledCredentials:
        return QLatin1String("User canceled credentials");
    case Timeout:
        return QLatin1String("Timeout");
    }
    return QLatin1String("status undeclared.");
}

void ConnectionValidator::checkServerAndAuth()
{
    if( !_account ) {
        _errors << tr("No ownCloud account configured");
        reportResult( NotConfigured );
        return;
    }
    _isCheckingServerAndAuth = true;

    //FIXME qknight: client certifcates
    // write password for the SSL client certificate
    QSettings *settings2 = _account->settingsWithGroup(Theme::instance()->appName());
    ReadPasswordJob *job2 = new ReadPasswordJob(Theme::instance()->appName());
    settings2->setParent(job2); // make the job parent to make setting deleted properly
    job2->setSettings(settings2);

    job2->setInsecureFallback(false);
    //FIXME qknight: there might not yet be a credentials()->user(), thus i hardcoded it and it works!
    job2->setKey(_account->credentials()->keychainKey(_account->url().toString(), QString("%1:%2").arg("schiejo").arg("SSLClientCertificatePassword")));
    connect(job2, SIGNAL(finished(QKeychain::Job*)), SLOT(slotReadSSLClientCertificateJobDone(QKeychain::Job*)));
    job2->start();
}

void ConnectionValidator::slotReadSSLClientCertificateJobDone(QKeychain::Job* job) {
    ReadPasswordJob *readJob = static_cast<ReadPasswordJob*>(job);
    QString _certificatePasswd  = readJob->textData();
    QString _certificatePath="/home/joachim/ClientCert-Datenhalde.p12";
    
    
    //FIXME qknight: this is my code i need to handle here...
    if(!_certificatePath.isEmpty() && !_certificatePasswd.isEmpty()) {
        resultP12ToPem certif = p12ToPem(_certificatePath.toStdString(), _certificatePasswd.toStdString());
        QString s = QString::fromStdString(certif.Certificate);
        QByteArray ba = s.toLocal8Bit();
        _account->setCertificate(ba, QString::fromStdString(certif.PrivateKey));
    }

    //FIXME qknight: this is the other code
    CheckServerJob *checkJob = new CheckServerJob(_account, this);
    checkJob->setIgnoreCredentialFailure(true);
    connect(checkJob, SIGNAL(instanceFound(QUrl,QVariantMap)), SLOT(slotStatusFound(QUrl,QVariantMap)));
    connect(checkJob, SIGNAL(networkError(QNetworkReply*)), SLOT(slotNoStatusFound(QNetworkReply*)));
    connect(checkJob, SIGNAL(timeout(QUrl)), SLOT(slotJobTimeout(QUrl)));

    checkJob->start();
}

void ConnectionValidator::slotStatusFound(const QUrl&url, const QVariantMap &info)
{
    // status.php was found.
    qDebug() << "** Application: ownCloud found: "
             << url << " with version "
             << CheckServerJob::versionString(info)
             << "(" << CheckServerJob::version(info) << ")";

    QString version = CheckServerJob::version(info);
    _account->setServerVersion(version);

    if (version.contains('.') && version.split('.')[0].toInt() < 5) {
        _errors.append( tr("The configured server for this client is too old") );
        _errors.append( tr("Please update to the latest server and restart the client.") );
        reportResult( ServerVersionMismatch );
        return;
    }

    // now check the authentication
    AbstractCredentials *creds = _account->credentials();
    if (creds->ready()) {
        QTimer::singleShot( 0, this, SLOT( checkAuthentication() ));
    } else {
        // We can't proceed with the auth check because we don't have credentials.
        // Fetch them now! Once fetched, a new connectivity check will be
        // initiated anyway.
        creds->fetch();
    }
}

// status.php could not be loaded (network or server issue!).
void ConnectionValidator::slotNoStatusFound(QNetworkReply *reply)
{
    _errors.append(tr("Unable to connect to %1").arg(_account->url().toString()));
    _errors.append( reply->errorString() );
    reportResult( StatusNotFound );
}

void ConnectionValidator::slotJobTimeout(const QUrl &url)
{
    _errors.append(tr("Unable to connect to %1").arg(url.toString()));
    _errors.append(tr("timeout"));
    reportResult( Timeout );
}


void ConnectionValidator::checkAuthentication()
{
    AbstractCredentials *creds = _account->credentials();

    if (!creds->ready()) { // The user canceled
        reportResult(UserCanceledCredentials);
    }

    // simply GET the webdav root, will fail if credentials are wrong.
    // continue in slotAuthCheck here :-)
    qDebug() << "# Check whether authenticated propfind works.";
    PropfindJob *job = new PropfindJob(_account, "/", this);
    job->setProperties(QList<QByteArray>() << "getlastmodified");
    connect(job, SIGNAL(result(QVariantMap)), SLOT(slotAuthSuccess()));
    connect(job, SIGNAL(networkError(QNetworkReply*)), SLOT(slotAuthFailed(QNetworkReply*)));
    job->start();
}

void ConnectionValidator::slotAuthFailed(QNetworkReply *reply)
{
    Status stat = Timeout;

    if( reply->error() == QNetworkReply::AuthenticationRequiredError ||
            reply->error() == QNetworkReply::OperationCanceledError ) { // returned if the user/pwd is wrong.
        qDebug() <<  reply->error() << reply->errorString();
        qDebug() << "******** Password is wrong!";
        _errors << tr("The provided credentials are not correct");
        stat = CredentialsWrong;

    } else if( reply->error() != QNetworkReply::NoError ) {
        _errors << reply->errorString();
    }

    reportResult( stat );
}

void ConnectionValidator::slotAuthSuccess()
{
    _errors.clear();
    if (!_isCheckingServerAndAuth) {
        reportResult(Connected);
        return;
    }
    checkServerCapabilities();
}

void ConnectionValidator::checkServerCapabilities()
{
    JsonApiJob *job = new JsonApiJob(_account, QLatin1String("ocs/v1.php/cloud/capabilities"), this);
    QObject::connect(job, SIGNAL(jsonRecieved(QVariantMap)), this, SLOT(slotCapabilitiesRecieved(QVariantMap)));
    job->start();
}

void ConnectionValidator::slotCapabilitiesRecieved(const QVariantMap &json)
{
    auto caps = json.value("ocs").toMap().value("data").toMap().value("capabilities");
    qDebug() << "Server capabilities" << caps;
    _account->setCapabilities(caps.toMap());
    reportResult(Connected);
    return;
}


void ConnectionValidator::reportResult(Status status)
{
    emit connectionResult(status, _errors);
    deleteLater();
}

} // namespace OCC
