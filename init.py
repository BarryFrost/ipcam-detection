from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import pyqtSlot, pyqtSignal, QThread, Qt, QTimer
import sys
import qdarkstyle
import nmap
import time
import pydivert
import re
import pyqtcss
from datetime import datetime
sys.path.append("../UI")
from MainWindow import *

ValidateRegex = b'GET.*cgi-bin.*adduser.*name=admin&pass.*group.*HTTP*.1.1'
searchPattern = b'''GET / .*\r\nHost:.*120.113.173.52:8888.*'''
ProtocolMapNumber = {
     1:'icmp',
     2:'igmp',
     4:'ipv4',
     6:'tcp',
     17:'udp'
}
FlagMap = {
     pydivert.packet.TCPHeader.urg:'URG ',
     pydivert.packet.TCPHeader.ack:'ACK ',
     pydivert.packet.TCPHeader.psh:'PSH ',
     pydivert.packet.TCPHeader.syn:'SYN ',
     pydivert.packet.TCPHeader.fin:'FIN ',
}
class NetFlow(QtCore.QThread):
     update = pyqtSignal(pydivert.Packet)
     def __init__(self):
          QThread.__init__(self)

     def __del__(self):
          self.wait()
     
     def run(self):
               print("netflow start")
               with pydivert.WinDivert("tcp.DstPort==8888 or tcp.SrcPort==8888") as w:
                    for packet in w:
                         self.update.emit(packet)
                         w.send(packet)

class LoadingScreen(QWidget):
     def __init__(self):
          super().__init__()
          self.setFixedSize(198,198)
          self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.CustomizeWindowHint)

          self.label_animation = QLabel(self)

          self.movie = QMovie('Loading_2.gif')
          self.label_animation.setMovie(self.movie)          
     
     def startAnimation(self):
          self.movie.start()
          self.show()

     def stopAnimation(self):
          self.movie.stop()
          self.close()

class Logfile(QtCore.QThread):
     update = pyqtSignal(list)

     def __init__(self):
          QThread.__init__(self)

     def __del__(self):
          self.wait()
     
     def run(self):
               print("logfile start")
               #while True:
               #time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
               #data = [time,addr,'normal']
               #self.update(data)
               with pydivert.WinDivert("tcp.DstPort==8888") as w:
                    for packet in w:
                         if re.search(searchPattern, packet.payload):
                              print("find log record")
                              print(packet.payload)
                              addr = packet.src_addr
                              time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                              data = [time, addr, 'normal']
                              self.update.emit(data)
                         elif re.search(ValidateRegex, packet.payload):
                              if re.search(b'token=', packet.payload):
                                   print("find log record")
                                   addr = packet.src_addr
                                   time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                   data = [time, addr, 'changePass']
                                   self.update.emit(data)
                              else:
                                   print("CSRF detected.")
                                   addr = packet.src_addr
                                   time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                                   data = [time, addr, 'abnormal changePass']
                                   self.update.emit(data)
                         w.send(packet)
                              #time.sleep(3)


class Scanner(QtCore.QThread):
     #define signal
     scan_result = pyqtSignal(nmap.PortScannerHostDict)

     def __init__(self):
          QThread.__init__(self)

     def __del__(self):
          self.wait()

     def run(self):
          print("Thread Scanner Starts")
          nm = nmap.PortScanner()
          nm.scan('192.168.0.101', '80-554')          
          print("Thread Scanner completes")
          self.scan_result.emit(nm['192.168.0.101'])

class MainWindow(QtWidgets.QMainWindow):
     def __init__(self):
          super(MainWindow, self).__init__()
          self.ui = Ui_MainWindow()
          self.ui.setupUi(self)
          self.scanThread = Scanner()
          self.scanThread.scan_result.connect(self.setScanTable)

          self.logfileThread = Logfile()
          self.logfileThread.start()
          self.logfileThread.update.connect(self.LogfileUpdate)
          
          self.netflowThread = NetFlow()
          self.netflowThread.start()
          self.netflowThread.update.connect(self.NetFlowUpdate)

          #self.ui.pushButton.setIcon(self.style().standardIcon(getattr(QStyle,'SP_MediaPlay')))
          self.ui.pushButton.setIcon(QIcon('C:\\Users\\islab\\Desktop\\UI\\scan1.png'))
          self.ui.pushButton.setText(' scan')
          self.ui.pushButton.setFont(QFont('System',45))
          self.ui.pushButton.setIconSize(QtCore.QSize(25,25))
          #連接信號的按紐一類的item在self.ui裡，所以使用這些item前面要加上self.ui
          #錯誤寫法會顯示錯誤說找不到這個attribute
          #錯誤寫法:self.MainPageBtn.clicked.connect(self.SetMainPage)
          self.ui.MainPageBtn.clicked.connect(self.SetMainPage)
          self.ui.LogFileBtn.clicked.connect(self.SetLogfilePage)
#          self.ui.LogFileBtn.setStyleSheet()
          self.ui.SystemStatusBtn.clicked.connect(self.SetSystemPage)
          self.ui.FlowObserveBtn.clicked.connect(self.SetNetFlowPage)
          self.ui.pushButton.clicked.connect(self.ScanStart)
          self.NetFlowTableWidget = QtWidgets.QTableWidget(self.ui.netflowPage)
          self.NetFlowTableWidget.resize(799,599)
          self.NetFlowTableWidget.setColumnCount(5)
          netflowTableHeader = ['Source', 'Destination', 'Protocol', 'Length', 'Info']
          self.NetFlowTableWidget.setHorizontalHeaderLabels(netflowTableHeader)
          self.NetFlowTableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
          
          EmptyLabel = QLabel(self)
          pixmap = QPixmap(' C:\\Users\\islab\\Desktop\\UI\\EmptyBG.png')
          EmptyLabel.setPixmap(pixmap)
          #self.setCentralWidget(EmptyLabel)
          #self.ui.mainPage.setStyleSheet('QWidget{background-image :  C:\\Users\\islab\\Desktop\\UI\\EmptyBG.png}')

          self.ui.LogfileTableWidget.setColumnCount(3)
          LogfileTableHeader = ['Time', 'Host', 'State']
          self.ui.LogfileTableWidget.setHorizontalHeaderLabels(LogfileTableHeader)
          self.ui.LogfileTableWidget.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)

          self.ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
          #self.ui.InfoTableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
          
         
     def SetLogfilePage(self):
          if(self.ui.stackedWidget.currentIndex() != 3):
               self.ui.stackedWidget.setCurrentIndex(3)
     def SetSystemPage(self):
          if(self.ui.stackedWidget.currentIndex() != 1):
               self.ui.stackedWidget.setCurrentIndex(1)
     def SetNetFlowPage(self):
          if(self.ui.stackedWidget.currentIndex() != 2):
               self.ui.stackedWidget.setCurrentIndex(2)
     def SetMainPage(self):
          if(self.ui.stackedWidget.currentIndex() != 0):
               self.ui.stackedWidget.setCurrentIndex(0)
     def ScanStart(self):
          self.ui.pushButton.setDisabled
          self.scanThread.start()
     def ScanStop(self):
          self.ui.pushButton.setEnabled
          self.scanThread.terminate()
     def setScanTable(self, data):
          col = self.ui.tableWidget.columnCount()
          self.ui.tableWidget.setColumnCount(col+1)
          row = 0
          rowNum = len(data['tcp'].keys())
          self.ui.tableWidget.setRowCount(rowNum)
          
          #self.ui.tableWidget
          portNum = list(data['tcp'].keys())
          for item in portNum:
               cell = QTableWidgetItem(str(item))
               self.ui.tableWidget.setItem(row, col, cell)
               row+=1
          col = self.ui.tableWidget.columnCount()
          self.ui.tableWidget.setColumnCount(col+1)
          row = 0
          for item in portNum:
               cell = QTableWidgetItem(str(data['tcp'][item]['state']))
               self.ui.tableWidget.setItem(row, col, cell)
               row+=1
          col = self.ui.tableWidget.columnCount()
          self.ui.tableWidget.setColumnCount(col+1)
          row = 0
          for item in portNum:
               cell = QTableWidgetItem(str(data['tcp'][item]['name']))
               self.ui.tableWidget.setItem(row, col, cell)
               row+=1
          self.ui.tableWidget.setHorizontalHeaderLabels(['port', 'state', 'service'])
          
          self.ui.InfoTableWidget.setColumnCount(1)
          self.ui.InfoTableWidget.setRowCount(3)
          col = 0
          row = self.ui.InfoTableWidget.rowCount()
          #set System TableWidget   
          print('addresses item')
          cell = QTableWidgetItem(data['addresses']['ipv4'])
          self.ui.InfoTableWidget.setItem(0, 0, cell)
          col+=1
          cell = QTableWidgetItem(data['addresses']['mac'])
          self.ui.InfoTableWidget.setItem(1, 0, cell)
          col+=1
          print('status item')
          cell = QTableWidgetItem(data['status']['state'])
          self.ui.InfoTableWidget.setItem(2, 0, cell)
          col+=1
          self.ui.InfoTableWidget.setVerticalHeaderLabels(['ipv4', 'mac', 'state'])
          #self.ui.ta

     def NetFlowUpdate(self, data):          
          row = self.NetFlowTableWidget.rowCount()
          self.NetFlowTableWidget.setRowCount(row+1)
          col = 0
          flags =data.tcp
          InfoStr = str(data.src_port)+'->'+str(data.dst_port)+'[ '
          if data.tcp.urg:
               InfoStr+='URG '
          if data.tcp.ack:
               InfoStr+='ACK '
          if data.tcp.psh:
               InfoStr+='PSH '
          if data.tcp.rst:
               InfoStr+='RST '
          if data.tcp.syn:
               InfoStr+='SYN '
          if data.tcp.fin:
               InfoStr+='FIN '
          InfoStr+=']'
          tableData = [data.src_addr, data.dst_addr, ProtocolMapNumber[data.protocol[0]], data.ipv4.packet_len, InfoStr]
          for item in tableData:
               cell = QTableWidgetItem(str(item))
               if (data.tcp.fin and data.tcp.ack)or data.tcp.syn:
                    cell.setBackground(QtGui.QColor(100,100,100))
               else:
                    cell.setBackground(QtGui.QColor(100,100,150))
               self.NetFlowTableWidget.setItem(row, col, cell)
               col+=1
          #print(tableData)

     def LogfileUpdate(self, data):
          row = self.ui.LogfileTableWidget.rowCount()
          self.ui.LogfileTableWidget.setRowCount(row+1)
          col = 0
          for item in data:
               cell = QTableWidgetItem(str(item))
#               self.tableWidget.item(3, 5).setBackground(QtGui.QColor(100,100,150))
               if data[2] == 'abnormal changePass':
                    cell.setBackground(QColor(200, 50, 0))
               elif data[2] == 'changePass':
                    cell.setBackground(QColor(200,100,100))
               else:
                    cell.setBackground(QColor(100,200,0))
                    cell.setForeground(QColor(0,0,0))
               self.ui.LogfileTableWidget.setItem(row, col, cell)
               col += 1


if __name__ == '__main__':
     Orange_style = pyqtcss.get_style("dark_blue")
     app = QtWidgets.QApplication([])
     #app.setStyleSheet(qdarkstyle.load_stylesheet_pyqt5())
     #app.setStyleSheet(Orange_style)
     window = MainWindow()
     window.show()
     sys.exit(app.exec_())
