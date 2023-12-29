#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "pkt_handler.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <time.h>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QStyle>
#include <QtWidgets/QInputDialog>
#include <QtGui/QAction>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent): QMainWindow(parent), ui(new Ui::MainWindow) // 생성자
{
    ui->setupUi(this);

    /* TooBar Setting */
    QAction* openAction = new QAction("Open");
    QIcon open_icon = QApplication::style()->standardIcon(QStyle::SP_FileIcon);
    openAction->setIcon(open_icon);
    openAction->setStatusTip("Open");

    QAction* playAction = new QAction("Play");
    QIcon play_icon = QApplication::style()->standardIcon(QStyle::SP_MediaPlay);
    playAction->setIcon(play_icon);
    playAction->setStatusTip("Play");

    QAction* stopAction = new QAction("Stop");
    QIcon stop_icon = QApplication::style()->standardIcon(QStyle::SP_MediaStop);
    stopAction->setIcon(stop_icon);
    stopAction->setStatusTip("Stop");

    QToolBar* toolBar = this->addToolBar("ToolBar");

    toolBar->addAction(openAction);
    toolBar->addSeparator();
    toolBar->addAction(playAction);
    toolBar->addSeparator();
    toolBar->addAction(stopAction);

    /* Table Setting */
    ui->pkt_table->verticalHeader()->setVisible(false);
    ui->pkt_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->pkt_table->setShowGrid(true);
    setHeader();

    connect(openAction, SIGNAL(triggered()), this, SLOT(getPath()));
    connect(playAction, SIGNAL(triggered()), this, SLOT(playPkt()));
    connect(stopAction, SIGNAL(triggered()), this, SLOT(stopPkt()));
}

MainWindow::~MainWindow() // 소멸자
{
    delete ui;
}

void MainWindow::setHeader()
{
    QStringList header = { "No.", "Time", "Source", "Destination", "Protocol", "Length", "Info" }; // Header
    model = new QStandardItemModel();
    model->setHorizontalHeaderLabels(header);
    ui->pkt_table->setModel(model);
    col_max = header.length();
}

void MainWindow::getPath()
{
    QString qfile_path = QInputDialog::getText(this, "Open Capture File", "Please enter the capture file path");
    strcpy(file_path, qfile_path.toStdString().c_str());
}

void MainWindow::playPkt()
{
    /* Open the capture file */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* fp = pcap_open_offline(file_path, errbuf);
    FILE* save_file = fopen("test.txt", "w");

    /* start the capture */
    pcap_loop(fp, 0, packet_handler, (u_char*)save_file);

    std::string line;
    std::ifstream file("test.txt");
    int idx = 0;

    while (std::getline(file, line))
    {
        QList<QStandardItem*> row;
        row.append(new QStandardItem(QString::number(++idx)));

        std::istringstream sline(line);
        std::string buff;
        while (std::getline(sline, buff, '\t'))
        {
            row.append(new QStandardItem(QString::fromStdString(buff)));
        }
        model->appendRow(row);
    }
}

void MainWindow::stopPkt()
{
    QMessageBox msgbox;
    msgbox.setText("Do you really want to reset?");
    msgbox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
    msgbox.setDefaultButton(QMessageBox::Ok);

    int ans = msgbox.exec();

    if (ans == QMessageBox::Ok)
    {
        setHeader();
    }
}
