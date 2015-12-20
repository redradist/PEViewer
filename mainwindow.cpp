#include "mainwindow.h"
#include "peloader.h"
#include "ui_mainwindow.h"

#include <QFile>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QTreeWidgetItem * MainWindow::AddRoot(QString name)
{
    QTreeWidgetItem* root = new QTreeWidgetItem(ui->treeWidget);

    root->setText(0, name);
    ui->treeWidget->addTopLevelItem(root);

    return root;
}

QTreeWidgetItem * MainWindow::AddChilren(QTreeWidgetItem *parent, QString name)
{
    QTreeWidgetItem* child = new QTreeWidgetItem(parent);
    child->setText(0, name);
    parent->addChild(child);

    return child;
}

void MainWindow::on_lineEdit_textChanged(const QString &file)
{
    pefile = file.toStdWString();
}

void MainWindow::on_buttonPush_clicked()
{
    HANDLE handle = pefile.GetModuleDetail();
    if(handle != NULL)
    {
        QTreeWidgetItem* ptwgItem = NULL;
        QTreeWidgetItem* ptwgItemDir = NULL;
        QTreeWidgetItem* ptwgItemSubDir = NULL;
        QTreeWidgetItem* twItem = NULL;
        ptwgItem = AddRoot(QString("Signature = ")+QString::number(IMAGE_GET_NTHEADER(handle)->Signature));
        ptwgItem = AddRoot(QString("FileHeader"));
        AddChilren(ptwgItem, QString("Machine = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.Machine));
        AddChilren(ptwgItem, QString("NumberOfSections = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.NumberOfSections));
        AddChilren(ptwgItem, QString("TimeDateStamp = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.TimeDateStamp));
        AddChilren(ptwgItem, QString("PointerToSymbolTable = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.PointerToSymbolTable));
        AddChilren(ptwgItem, QString("NumberOfSymbols = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.NumberOfSymbols));
        AddChilren(ptwgItem, QString("SizeOfOptionalHeader = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.SizeOfOptionalHeader));
        AddChilren(ptwgItem, QString("Characteristics = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.Characteristics));
        ptwgItem = AddRoot(QString("OptionalHeader"));
        ptwgItemDir = AddChilren(ptwgItem, QString("Standard  fields"));
        AddChilren(ptwgItemDir, QString("Magic = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Magic));
        AddChilren(ptwgItemDir, QString("MajorLinkerVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorLinkerVersion));
        AddChilren(ptwgItemDir, QString("MinorLinkerVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorLinkerVersion));
        AddChilren(ptwgItemDir, QString("SizeOfCode = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfCode));
        AddChilren(ptwgItemDir, QString("SizeOfInitializedData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfInitializedData));
        AddChilren(ptwgItemDir, QString("SizeOfUninitializedData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData));
        AddChilren(ptwgItemDir, QString("AddressOfEntryPoint = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData));
        AddChilren(ptwgItemDir, QString("BaseOfCode = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData));
        AddChilren(ptwgItemDir, QString("BaseOfData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.BaseOfData));
        ptwgItemDir = AddChilren(ptwgItem, QString("NT additional fields"));
        AddChilren(ptwgItemDir, QString("ImageBase = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData));
        AddChilren(ptwgItemDir, QString("SectionAlignment = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfInitializedData));
        AddChilren(ptwgItemDir, QString("FileAlignment = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.FileAlignment));
        AddChilren(ptwgItemDir, QString("MajorOperatingSystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorOperatingSystemVersion));
        AddChilren(ptwgItemDir, QString("MinorOperatingSystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorOperatingSystemVersion));
        AddChilren(ptwgItemDir, QString("MajorImageVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorImageVersion));
        AddChilren(ptwgItemDir, QString("MinorImageVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorImageVersion));
        AddChilren(ptwgItemDir, QString("MajorSubsystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorSubsystemVersion));
        AddChilren(ptwgItemDir, QString("MinorSubsystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorSubsystemVersion));
        AddChilren(ptwgItemDir, QString("Win32VersionValue = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Win32VersionValue));
        AddChilren(ptwgItemDir, QString("SizeOfImage = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfImage));
        AddChilren(ptwgItemDir, QString("SizeOfHeaders = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeaders));
        AddChilren(ptwgItemDir, QString("CheckSum = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.CheckSum));
        AddChilren(ptwgItemDir, QString("Subsystem = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Subsystem));
        AddChilren(ptwgItemDir, QString("DllCharacteristics = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DllCharacteristics));
        AddChilren(ptwgItemDir, QString("SizeOfStackReserve = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfStackReserve));
        AddChilren(ptwgItemDir, QString("SizeOfStackCommit = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfStackCommit));
        AddChilren(ptwgItemDir, QString("SizeOfHeapReserve = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeapReserve));
        AddChilren(ptwgItemDir, QString("SizeOfHeapCommit = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeapCommit));
        AddChilren(ptwgItemDir, QString("LoaderFlags = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.LoaderFlags));
        AddChilren(ptwgItemDir, QString("NumberOfRvaAndSizes = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.NumberOfRvaAndSizes));
        ptwgItemSubDir = AddChilren(ptwgItemDir, QString("DataDirectory"));
        for(int i = 0; i < IMAGE_GET_NTHEADER(handle)->OptionalHeader.NumberOfRvaAndSizes;i++)
        {
            twItem = AddChilren(ptwgItemSubDir, QString("[")+QString::number(i)+"]");
            AddChilren(twItem, QString("VirtualAddress = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DataDirectory[i].VirtualAddress));
            AddChilren(twItem, QString("Size = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DataDirectory[i].Size));
        }
        saveFile(handle, "pe_module.pee");
    }
}

/*
 * Save base of data to file
 * */
bool MainWindow::saveFile(HANDLE handle, QString file)
{
    QFile *logFile = new QFile(file);

    // Checking, can we take file for read ?
    if (logFile->open(QFile::ReadWrite | QFile::Truncate))
    {
        QString str;
        QTextStream out(logFile);

        str += QString("Signature = ")+QString::number(IMAGE_GET_NTHEADER(handle)->Signature) + ';\r\n';
        str += QString("FileHeader") + ';\r\n';
        str += QString("Machine = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.Machine) + ';\r\n';
        str += QString("NumberOfSections = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.NumberOfSections) + ';\r\n';
        str += QString("TimeDateStamp = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.TimeDateStamp) + ';\r\n';
        str += QString("PointerToSymbolTable = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.PointerToSymbolTable) + ';\r\n';
        str += QString("NumberOfSymbols = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.NumberOfSymbols) + ';\r\n';
        str += QString("SizeOfOptionalHeader = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.SizeOfOptionalHeader) + ';\r\n';
        str += QString("Characteristics = ")+QString::number(IMAGE_GET_NTHEADER(handle)->FileHeader.Characteristics) + ';\r\n';
        str += QString("OptionalHeader") + ';\r\n';
        str += QString("Standard  fields") + ';\r\n';
        str += QString("Magic = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Magic) + ';\r\n';
        str += QString("MajorLinkerVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorLinkerVersion) + ';\r\n';
        str += QString("MinorLinkerVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorLinkerVersion) + ';\r\n';
        str += QString("SizeOfCode = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfCode) + ';\r\n';
        str += QString("SizeOfInitializedData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfInitializedData) + ';\r\n';
        str += QString("SizeOfUninitializedData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData) + ';\r\n';
        str += QString("AddressOfEntryPoint = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData) + ';\r\n';
        str += QString("BaseOfCode = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData) + ';\r\n';
        str += QString("BaseOfData = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.BaseOfData) + ';\r\n';
        str += QString("NT additional fields") + ';\r\n';
        str += QString("ImageBase = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfUninitializedData) + ';\r\n';
        str += QString("SectionAlignment = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfInitializedData) + ';\r\n';
        str += QString("FileAlignment = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.FileAlignment) + ';\r\n';
        str += QString("MajorOperatingSystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorOperatingSystemVersion) + ';\r\n';
        str += QString("MinorOperatingSystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorOperatingSystemVersion) + ';\r\n';
        str += QString("MajorImageVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorImageVersion) + ';\r\n';
        str += QString("MinorImageVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorImageVersion) + ';\r\n';
        str += QString("MajorSubsystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MajorSubsystemVersion) + ';\r\n';
        str += QString("MinorSubsystemVersion = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.MinorSubsystemVersion) + ';\r\n';
        str += QString("Win32VersionValue = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Win32VersionValue) + ';\r\n';
        str += QString("SizeOfImage = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfImage) + ';\r\n';
        str += QString("SizeOfHeaders = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeaders) + ';\r\n';
        str += QString("CheckSum = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.CheckSum) + ';\r\n';
        str += QString("Subsystem = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.Subsystem) + ';\r\n';
        str += QString("DllCharacteristics = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DllCharacteristics) + ';\r\n';
        str += QString("SizeOfStackReserve = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfStackReserve) + ';\r\n';
        str += QString("SizeOfStackCommit = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfStackCommit) + ';\r\n';
        str += QString("SizeOfHeapReserve = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeapReserve) + ';\r\n';
        str += QString("SizeOfHeapCommit = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.SizeOfHeapCommit) + ';\r\n';
        str += QString("LoaderFlags = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.LoaderFlags) + ';\r\n';
        str += QString("NumberOfRvaAndSizes = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.NumberOfRvaAndSizes) + ';\r\n';
        str += QString("DataDirectory") + ';\r\n';
        for(int i = 0; i < IMAGE_GET_NTHEADER(handle)->OptionalHeader.NumberOfRvaAndSizes;i++)
        {
            str += QString("[") + QString::number(i) + '];\r\n';
            str += QString("VirtualAddress = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DataDirectory[i].VirtualAddress) + ';\r\n';
            str += QString("Size = ")+QString::number(IMAGE_GET_NTHEADER(handle)->OptionalHeader.DataDirectory[i].Size) + ';\r\n';
        }
        out << str;
    }
    else
    {
        qDebug() << "Can't open file, may be file is not exist ?";
        logFile->close();
        return false;
    }

    logFile->close();
    delete logFile;
    return true;
}

void MainWindow::on_pushButton_clicked()
{
    ui->treeWidget->clear();
    pefile.CloseModule();
}
