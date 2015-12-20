#include "mainwindow.h"
#include <QApplication>
#include "peloader.h"

#ifdef SEH
LONG CALLBACK TopLevelExceptionFilter( EXCEPTION_POINTERS *ExceptionInfo )
{
  if (
      ::MessageBox(
      ::GetDesktopWindow(),
      __TEXT("Unhandled exception was detected.\nClose application?"),
      __TEXT("Peloader: error"),
      MB_OKCANCEL+MB_ICONERROR
    ) == IDOK
    ) ::ExitProcess(0);
  return EXCEPTION_EXECUTE_HANDLER;
}
#endif

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
#ifdef SEH
    // enables an application to supersede the top-level exception handler
    // of each thread and process
    SetUnhandledExceptionFilter( TopLevelExceptionFilter );
#endif
    //LoadExe(__TEXT("D:\\Projects_Programing\\IBM_PC\\ServiceManager\\ServiceManager\\ServiceManager.exe"));
    //::ExitProcess(0);
    w.show();
    return a.exec();
}
