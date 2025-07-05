/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.9.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtGui/QIcon>
#include <QtWidgets/QApplication>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralwidget;
    QWidget *horizontalLayoutWidget;
    QHBoxLayout *horizontalLayout;
    QTextEdit *fileTextEdit;
    QPushButton *selectFileButton;
    QPushButton *startButton;
    QPushButton *clearButton;
    QWidget *horizontalLayoutWidget_2;
    QHBoxLayout *horizontalLayout_2;
    QTreeWidget *treeWidget;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout_5;
    QLabel *processNameLable;
    QLabel *processName;
    QHBoxLayout *horizontalLayout_3;
    QLabel *processIdLabel;
    QLabel *processId;
    QHBoxLayout *horizontalLayout_4;
    QLabel *processPriorityLabel;
    QLabel *processPriority;
    QLabel *processInfoLabel;
    QTextEdit *processInfoTextEdit;
    QLabel *warningLabel;
    QTextEdit *warningTextEdit;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(804, 629);
        QIcon icon;
        icon.addFile(QString::fromUtf8("../redpill.png"), QSize(), QIcon::Mode::Normal, QIcon::State::Off);
        MainWindow->setWindowIcon(icon);
        centralwidget = new QWidget(MainWindow);
        centralwidget->setObjectName("centralwidget");
        horizontalLayoutWidget = new QWidget(centralwidget);
        horizontalLayoutWidget->setObjectName("horizontalLayoutWidget");
        horizontalLayoutWidget->setGeometry(QRect(0, 0, 801, 41));
        horizontalLayout = new QHBoxLayout(horizontalLayoutWidget);
        horizontalLayout->setObjectName("horizontalLayout");
        horizontalLayout->setContentsMargins(0, 0, 0, 0);
        fileTextEdit = new QTextEdit(horizontalLayoutWidget);
        fileTextEdit->setObjectName("fileTextEdit");
        fileTextEdit->setMinimumSize(QSize(500, 30));
        fileTextEdit->setMaximumSize(QSize(500, 30));

        horizontalLayout->addWidget(fileTextEdit);

        selectFileButton = new QPushButton(horizontalLayoutWidget);
        selectFileButton->setObjectName("selectFileButton");

        horizontalLayout->addWidget(selectFileButton);

        startButton = new QPushButton(horizontalLayoutWidget);
        startButton->setObjectName("startButton");

        horizontalLayout->addWidget(startButton);

        clearButton = new QPushButton(horizontalLayoutWidget);
        clearButton->setObjectName("clearButton");

        horizontalLayout->addWidget(clearButton);

        horizontalLayoutWidget_2 = new QWidget(centralwidget);
        horizontalLayoutWidget_2->setObjectName("horizontalLayoutWidget_2");
        horizontalLayoutWidget_2->setGeometry(QRect(0, 40, 801, 541));
        horizontalLayout_2 = new QHBoxLayout(horizontalLayoutWidget_2);
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        horizontalLayout_2->setContentsMargins(0, 0, 0, 0);
        treeWidget = new QTreeWidget(horizontalLayoutWidget_2);
        treeWidget->setObjectName("treeWidget");
        treeWidget->setMinimumSize(QSize(510, 531));
        treeWidget->setMaximumSize(QSize(510, 531));

        horizontalLayout_2->addWidget(treeWidget);

        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName("verticalLayout");
        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName("horizontalLayout_5");
        processNameLable = new QLabel(horizontalLayoutWidget_2);
        processNameLable->setObjectName("processNameLable");

        horizontalLayout_5->addWidget(processNameLable);

        processName = new QLabel(horizontalLayoutWidget_2);
        processName->setObjectName("processName");

        horizontalLayout_5->addWidget(processName);


        verticalLayout->addLayout(horizontalLayout_5);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName("horizontalLayout_3");
        processIdLabel = new QLabel(horizontalLayoutWidget_2);
        processIdLabel->setObjectName("processIdLabel");

        horizontalLayout_3->addWidget(processIdLabel);

        processId = new QLabel(horizontalLayoutWidget_2);
        processId->setObjectName("processId");

        horizontalLayout_3->addWidget(processId);


        verticalLayout->addLayout(horizontalLayout_3);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName("horizontalLayout_4");
        processPriorityLabel = new QLabel(horizontalLayoutWidget_2);
        processPriorityLabel->setObjectName("processPriorityLabel");

        horizontalLayout_4->addWidget(processPriorityLabel);

        processPriority = new QLabel(horizontalLayoutWidget_2);
        processPriority->setObjectName("processPriority");

        horizontalLayout_4->addWidget(processPriority);


        verticalLayout->addLayout(horizontalLayout_4);

        processInfoLabel = new QLabel(horizontalLayoutWidget_2);
        processInfoLabel->setObjectName("processInfoLabel");
        processInfoLabel->setMinimumSize(QSize(0, 30));
        processInfoLabel->setMaximumSize(QSize(16777215, 30));

        verticalLayout->addWidget(processInfoLabel);

        processInfoTextEdit = new QTextEdit(horizontalLayoutWidget_2);
        processInfoTextEdit->setObjectName("processInfoTextEdit");
        processInfoTextEdit->setMaximumSize(QSize(16777215, 150));

        verticalLayout->addWidget(processInfoTextEdit);

        warningLabel = new QLabel(horizontalLayoutWidget_2);
        warningLabel->setObjectName("warningLabel");
        warningLabel->setMinimumSize(QSize(0, 30));
        warningLabel->setMaximumSize(QSize(16777215, 30));

        verticalLayout->addWidget(warningLabel);

        warningTextEdit = new QTextEdit(horizontalLayoutWidget_2);
        warningTextEdit->setObjectName("warningTextEdit");
        warningTextEdit->setMinimumSize(QSize(0, 100));
        warningTextEdit->setMaximumSize(QSize(16777215, 100));

        verticalLayout->addWidget(warningTextEdit);


        horizontalLayout_2->addLayout(verticalLayout);

        MainWindow->setCentralWidget(centralwidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 804, 24));
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "RedPill", nullptr));
        selectFileButton->setText(QCoreApplication::translate("MainWindow", "\351\200\211\346\213\251\346\226\207\344\273\266", nullptr));
        startButton->setText(QCoreApplication::translate("MainWindow", "\345\274\200\345\247\213", nullptr));
        clearButton->setText(QCoreApplication::translate("MainWindow", "\346\270\205\351\231\244", nullptr));
        QTreeWidgetItem *___qtreewidgetitem = treeWidget->headerItem();
        ___qtreewidgetitem->setText(1, QCoreApplication::translate("MainWindow", "\350\257\246\347\273\206\344\277\241\346\201\257", nullptr));
        ___qtreewidgetitem->setText(0, QCoreApplication::translate("MainWindow", "API\345\220\215/\345\217\202\346\225\260", nullptr));
        processNameLable->setText(QCoreApplication::translate("MainWindow", "\350\277\233\347\250\213\345\220\215\357\274\232", nullptr));
        processName->setText(QString());
        processIdLabel->setText(QCoreApplication::translate("MainWindow", "\350\277\233\347\250\213ID\357\274\232", nullptr));
        processId->setText(QString());
        processPriorityLabel->setText(QCoreApplication::translate("MainWindow", "\350\277\233\347\250\213\346\235\203\351\231\220\357\274\232", nullptr));
        processPriority->setText(QString());
        processInfoLabel->setText(QCoreApplication::translate("MainWindow", "\350\277\233\347\250\213\344\277\241\346\201\257", nullptr));
        warningLabel->setText(QCoreApplication::translate("MainWindow", "\350\255\246\346\212\245", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
