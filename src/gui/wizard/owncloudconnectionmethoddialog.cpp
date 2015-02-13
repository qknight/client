#include "wizard/owncloudconnectionmethoddialog.h"
#include "utility.h"
#include <QUrl>

OwncloudConnectionMethodDialog::OwncloudConnectionMethodDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OwncloudConnectionMethodDialog)
{
    ui->setupUi(this);

    connect(ui->btnNoTLS, SIGNAL(clicked(bool)), this, SLOT(returnNoTLS()));
    connect(ui->btnClientSideTLS, SIGNAL(clicked(bool)), this, SLOT(returnClientSideTLS()));
    connect(ui->btnBack, SIGNAL(clicked(bool)), this, SLOT(returnBack()));

    // DM: TLS Client Cert GUI support disabled for now
//     ui->btnClientSideTLS->hide();
}

void OwncloudConnectionMethodDialog::setUrl(const QUrl &url)
{
    ui->label->setText(tr("<html><head/><body><p>Failed to connect to the secure server address <em>%1</em>. How do you wish to proceed?</p></body></html>")
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
        .arg(OCC::Utility::escape(url.toString())));
#else
        .arg(url.toDisplayString().toHtmlEscaped()));
#endif
}


void OwncloudConnectionMethodDialog::returnNoTLS()
{
    done(No_TLS);
}

void OwncloudConnectionMethodDialog::returnClientSideTLS()
{
    done(Client_Side_TLS);
}

void OwncloudConnectionMethodDialog::returnBack()
{
    done(Back);
}

OwncloudConnectionMethodDialog::~OwncloudConnectionMethodDialog()
{
    delete ui;
}
