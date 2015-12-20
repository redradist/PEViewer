#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTreeWidgetItem>
#include <QTextStream>
#include <QDebug>
#include "peloader.h"
namespace Ui {
class MainWindow;
}

class PELoader;

class MainWindow : public QMainWindow
{
    Q_OBJECT


public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    QTreeWidgetItem * AddRoot(QString name);
    QTreeWidgetItem * AddChilren(QTreeWidgetItem* parent, QString name);

private slots:
    void on_lineEdit_textChanged(const QString &arg1);

    void on_buttonPush_clicked();

    void on_pushButton_clicked();

private:
    Ui::MainWindow *ui;
    PELoader    pefile;

    bool saveFile(HANDLE handle, QString file);
};

#endif // MAINWINDOW_H
