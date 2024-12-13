import sys
import os

from PyQt5 import QtCore, QtWidgets

import logging
import volatility3.cli

from volatility3.framework.configuration import requirements
import io
from contextlib import redirect_stdout, redirect_stderr
from subprocess import Popen, PIPE
import threading

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(20, 10, 251, 21))
        self.lineEdit.setObjectName("lineEdit")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(280, 10, 75, 24))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(360, 10, 75, 24))
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(440, 10, 75, 24))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(520, 10, 75, 24))
        self.pushButton_4.setObjectName("pushButton_4")
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(20, 70, 751, 411))
        self.textBrowser.setObjectName("textBrowser")

        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(20, 40, 251, 21))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.pushButton_6 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_6.setGeometry(QtCore.QRect(280, 40, 75, 24))
        self.pushButton_6.setObjectName("pushButton_6")
    
    
        self.pushButton_5 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_5.setGeometry(QtCore.QRect(360, 40, 75, 24))
        self.pushButton_5.setObjectName("pushButton_5")
        
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 33))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.lineEdit.setText(_translate("MainWindow", "파일 경로"))
        self.pushButton.setText(_translate("MainWindow", "파일 찾기"))
        self.pushButton_2.setText(_translate("MainWindow", "파일 스캔"))
        self.pushButton_3.setText(_translate("MainWindow", "pf 목록 덤프"))
        self.pushButton_4.setText(_translate("MainWindow", "pf 목록 복구"))

        self.lineEdit_2.setText(_translate("MainWindow", "pf 찾을 경로"))
        self.pushButton_6.setText(_translate("MainWindow", "리스트 선택"))
        self.pushButton_5.setText(_translate("MainWindow", "리스트 pf스캔"))
        
        #self.ui.pushButton_6.clicked.connect(self.save_prefetch_list)
        #self.ui.pushButton_5.clicked.connect(self.analyze_prefetch_files)
class VolatilityWorker(QtCore.QThread):
    update_signal = QtCore.pyqtSignal(str)
    def __init__(self, plugin, memory_file, dump_file ='dump.csv'):
        super().__init__()
        self.plugin = plugin
        self.memory_file = memory_file
    def run(self):
        """Runs Volatility3 as a subprocess and streams output to both UI and a file."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = "mem_list.txt"  # 출력 파일
        try:
            if current_dir not in sys.path:
                sys.path.insert(0, current_dir)
    
            current_dir = os.path.dirname(os.path.abspath(__file__))
            vol_script = os.path.join(current_dir, "vol.py")
    
            command = [
                sys.executable,  # Python 실행 파일 경로
                vol_script,  # Volatility3 스크립트 실행
                "-f", self.memory_file,  # 메모리 덤프 파일
                self.plugin,  # 플러그인
            ]
            # 서브 프로세스 실행
            process = Popen(
                command,
                stdout=PIPE,  # 표준 출력 읽기
                stderr=PIPE,  # 표준 에러 읽기
                text=True,  # 텍스트 모드
                env={**os.environ, "PYTHONIOENCODING": "utf-8"}  # UTF-8 환경 변수 추가
            )
            # 파일 열기
            with open(output_file, "w", encoding="utf-8") as f:
                stdout_thread = threading.Thread(target=self.stream_output, args=(process.stdout, f))
                stderr_thread = threading.Thread(target=self.stream_output, args=(process.stderr, f, True))
    
                # 스레드 시작
                stdout_thread.start()
                stderr_thread.start()
    
                # 스레드 완료 대기
                stdout_thread.join()
                stderr_thread.join()
    
            process.wait()  # 프로세스 종료 대기
            self.update_signal.emit(f"Volatility 작업이 완료되었습니다. 출력 저장: {output_file}")
        except Exception as e:
            self.update_signal.emit(f"ERROR: {str(e)}")

    def stream_output(self, stream, file_handle, is_error=False):
        """Reads and sends output from a stream to both UI and a file."""
        try:
            for line in iter(stream.readline, ""):
                line = line.strip()
                if line:
                    # UTF-8 강제 처리
                    try:
                        line = line.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
                    except Exception as e:
                        line = f"Encoding Error: {str(e)} - Original: {line}"
    
                    # 파일에 저장
                    file_handle.write(line + "\n")
                    file_handle.flush()
    
                    # UI 갱신
                    if is_error:
                        self.update_signal.emit(f"ERROR: {line}")
                    else:
                        self.update_signal.emit(line)
        except Exception as e:
            self.update_signal.emit(f"Stream Error: {str(e)}")
        finally:
            stream.close()

class VolatilityDWorker(QtCore.QThread):
    update_signal = QtCore.pyqtSignal(str)

    def __init__(self, plugin, memory_file, dump_file ='dump.csv'):
        super().__init__()
        self.plugin = plugin
        self.memory_file = memory_file
        self.dump_dir = './dump'
        self.dump_file = dump_file

    def run(self):
        """Runs Volatility3 as a subprocess to dump Prefetch files based on the memory address."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = "pf_list.txt"  # 입력 파일
        try:
            if not os.path.exists(output_file):
                self.update_signal.emit(f"Prefetch 목록 파일이 존재하지 않습니다: {output_file}")
                return
            if not os.path.exists(self.memory_file):
                self.update_signal.emit(f"메모리 덤프 파일이 존재하지 않습니다: {self.memory_file}")
                return

            prefetch_directory = os.path.abspath(self.dump_dir)
            os.makedirs(prefetch_directory, exist_ok=True)
    
            with open(output_file, 'r', encoding='utf-8') as file:
                pf_lines = file.readlines()
    
            current_dir = os.path.dirname(os.path.abspath(__file__))
            vol_script = os.path.join(current_dir, "vol.py")
            
            for line in pf_lines:
                line = line.strip()
                if not line or "\\" not in line:
                    continue
    
                try:
                    parts = line.split()
                    memory_address = int(parts[0], 16)  # 메모리 주소는 첫 번째 필드
                    file_name = parts[-1]  # 파일명은 마지막 필드

                    self.update_signal.emit(f"덤프 중: 메모리 주소 {hex(memory_address)}, 파일명 {file_name}")
    
                    command = [
                    sys.executable,
                    vol_script,
                    "-f", self.memory_file,
                    "-o", prefetch_directory,
                    "windows.dumpfiles.DumpFiles",
                    f"--virtaddr={hex(memory_address)}"
                ]

                    process = Popen(
                        command,
                        stdout=PIPE,
                        stderr=PIPE,
                        text=True,
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
                    )
                    log_file_path = os.path.join(prefetch_directory, f"log.txt")
                    with open(log_file_path, "w", encoding="utf-8") as log_file:
                        # 스레드 실행
                        stdout_thread = threading.Thread(target=self.stream_output, args=(process.stdout, log_file))
                        stderr_thread = threading.Thread(target=self.stream_output, args=(process.stderr, log_file, True))
    
                        stdout_thread.start()
                        stderr_thread.start()
    
                        # 스레드 완료 대기
                        stdout_thread.join()
                        stderr_thread.join()
                    process.wait()  # 프로세스 종료 대기
                    if process.returncode != 0:
                        self.update_signal.emit(f"DumpFiles 명령어 실패 (exit code: {process.returncode})")
                    else:
                        self.update_signal.emit(f"DumpFiles 명령어 실행 성공: {file_name}")
                        
                except ValueError as e:
                    self.update_signal.emit(f"Prefetch 목록 구문 오류: {line}, {str(e)}")
                except Exception as e:
                    self.update_signal.emit(f"Prefetch 파일 덤프 실패: {line}, {str(e)}")
    
            self.update_signal.emit(f"Volatility 작업이 완료되었습니다. Prefetch 파일 덤프 경로: {prefetch_directory}")
        except Exception as e:
            self.update_signal.emit(f"ERROR: {str(e)}")


    def stream_output(self, stream, file_handle, is_error=False):
        """Reads and sends output from a stream to both UI and a file."""
        try:
            for line in iter(stream.readline, ""):
                line = line.strip()
                if line:
                    # UTF-8 강제 처리
                    try:
                        line = line.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
                    except Exception as e:
                        line = f"Encoding Error: {str(e)} - Original: {line}"
    
                    # 파일에 저장
                    file_handle.write(line + "\n")
                    file_handle.flush()
    
                    # UI 갱신
                    if is_error:
                        self.update_signal.emit(f"ERROR: {line}")
                    else:
                        self.update_signal.emit(line)
        except Exception as e:
            self.update_signal.emit(f"Stream Error: {str(e)}")
        finally:
            stream.close()
            
            

class VolatilitypfWorker(QtCore.QThread):
    update_signal = QtCore.pyqtSignal(str)

    def __init__(self, plugin, memory_file, dump_file ='dump.csv'):
        super().__init__()
        self.plugin = plugin
        self.memory_file = memory_file
        self.dump_dir = './dump'
        self.dump_file = dump_file

    def run(self):
        """Runs Volatility3 as a subprocess to dump Prefetch files based on the memory address."""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        output_file = "pf_list.txt"  # 입력 파일
        try:
            if not os.path.exists(output_file):
                self.update_signal.emit(f"Prefetch 목록 파일이 존재하지 않습니다: {output_file}")
                return
            if not os.path.exists(self.memory_file):
                self.update_signal.emit(f"메모리 덤프 파일이 존재하지 않습니다: {self.memory_file}")
                return

            prefetch_directory = os.path.abspath(self.dump_dir)
            os.makedirs(prefetch_directory, exist_ok=True)
    
            with open(output_file, 'r', encoding='utf-8') as file:
                pf_lines = file.readlines()
    
            current_dir = os.path.dirname(os.path.abspath(__file__))
            vol_script = os.path.join(current_dir, "vol.py")
            for line in pf_lines:
                line = line.strip()
                if not line or "\\" not in line:
                    continue
    
                try:
                    parts = line.split()
                    memory_address = int(parts[0], 16)  # 메모리 주소는 첫 번째 필드
                    file_name = parts[-1]  # 파일명은 마지막 필드

                    self.update_signal.emit(f"덤프 중: 메모리 주소 {hex(memory_address)}, 파일명 {file_name}")
    
                    command = [
                    sys.executable,
                    vol_script,
                    "-f", self.memory_file,
                    self.plugin
                ]

                    process = Popen(
                        command,
                        stdout=PIPE,
                        stderr=PIPE,
                        text=True,
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"}
                    )
                    log_file_path = os.path.join(prefetch_directory, f"log.txt")
                    with open(log_file_path, "w", encoding="utf-8") as log_file:
                        # 스레드 실행
                        stdout_thread = threading.Thread(target=self.stream_output, args=(process.stdout, log_file))
                        stderr_thread = threading.Thread(target=self.stream_output, args=(process.stderr, log_file, True))
    
                        stdout_thread.start()
                        stderr_thread.start()
    
                        # 스레드 완료 대기
                        stdout_thread.join()
                        stderr_thread.join()
                    process.wait()  # 프로세스 종료 대기
                    if process.returncode != 0:
                        self.update_signal.emit(f"DumpFiles 명령어 실패 (exit code: {process.returncode})")
                    else:
                        self.update_signal.emit(f"DumpFiles 명령어 실행 성공: {file_name}")
                        
                except ValueError as e:
                    self.update_signal.emit(f"Prefetch 목록 구문 오류: {line}, {str(e)}")
                except Exception as e:
                    self.update_signal.emit(f"Prefetch 파일 덤프 실패: {line}, {str(e)}")
    
            self.update_signal.emit(f"Volatility 작업이 완료되었습니다. Prefetch 파일 덤프 경로: {prefetch_directory}")
        except Exception as e:
            self.update_signal.emit(f"ERROR: {str(e)}")


    def stream_output(self, stream, file_handle, is_error=False):
        """Reads and sends output from a stream to both UI and a file."""
        try:
            for line in iter(stream.readline, ""):
                line = line.strip()
                if line:
                    # UTF-8 강제 처리
                    try:
                        line = line.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
                    except Exception as e:
                        line = f"Encoding Error: {str(e)} - Original: {line}"
    
                    # 파일에 저장
                    file_handle.write(line + "\n")
                    file_handle.flush()
    
                    # UI 갱신
                    if is_error:
                        self.update_signal.emit(f"ERROR: {line}")
                    else:
                        self.update_signal.emit(line)
        except Exception as e:
            self.update_signal.emit(f"Stream Error: {str(e)}")
        finally:
            stream.close()
class PrefetchAnalyzer(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # 버튼 클릭 이벤트 연결
        self.ui.pushButton.clicked.connect(self.select_file)
        self.ui.pushButton_2.clicked.connect(self.find_prefetch_list)
        self.ui.pushButton_3.clicked.connect(self.dump_prefetch_files)
        self.ui.pushButton_4.clicked.connect(self.recover_prefetch_files)
        self.ui.pushButton_5.clicked.connect(self.analyze_prefetch_files)
        self.ui.pushButton_6.clicked.connect(self.save_prefetch_list)

    def closeEvent(self, event):
        """Clean up logging handlers on close."""
        logger = logging.getLogger()
        for handler in logger.handlers[:]:
            logger.removeHandler(handler)
        super().closeEvent(event)

    def select_file(self):
        """메모리 덤프 파일 선택"""
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "메모리 덤프 파일 선택")
        if file_path:
            self.ui.lineEdit.setText(file_path)
            self.ui.textBrowser.append("파일 선택: {}".format(file_path))
    
    def find_prefetch_list(self):
        """Prefetch 목록 찾기"""
        memory_dump_file = self.ui.lineEdit.text()
        if not os.path.exists(memory_dump_file):
            self.ui.textBrowser.append("메모리 덤프 파일 경로가 유효하지 않습니다.")
            return

        self.ui.textBrowser.append("Prefetch 목록 찾는 중...")

        # VolatilityWorker 스레드 실행
        self.ui.textBrowser.append("Volatility 실행 중...")
        self.worker = VolatilityWorker("windows.filescan.FileScan", memory_dump_file)
        self.worker.update_signal.connect(self.update_text_browser)
        self.worker.finished.connect(
            lambda: self.ui.textBrowser.append("Volatility 작업이 완료되었습니다.")
        )  # 작업 완료 시 TextBrowser에 메시지 추가
        self.worker.start()
        current_dir = os.path.dirname(os.path.abspath(__file__))
        mem_name = os.path.join(current_dir, "mem_list.txt")
        self.ui.lineEdit_2.setText(mem_name)

    def update_text_browser(self, message):
        """QTextBrowser에 메시지 업데이트"""
        try:
            # 강제 UTF-8 디코딩
            message = message.encode("latin1", errors="ignore").decode("utf-8", errors="ignore")
        except UnicodeDecodeError:
            message = "Decoding Error 발생: " + repr(message)
    
        self.ui.textBrowser.append(message)
        self.ui.textBrowser.ensureCursorVisible()
        
    def dump_prefetch_files(self):
        """Prefetch 파일을 Volatility3를 사용해 덤프"""
        memory_dump_file = self.ui.lineEdit.text()  # 메모리 덤프 파일 경로
        pf_list_file = self.ui.lineEdit_2.text()  # 저장할 pf 목록 파일 경로
    
        if not os.path.exists(memory_dump_file):
            self.ui.textBrowser.append(f"메모리 덤프 파일 경로가 유효하지 않습니다: {memory_dump_file}")
            return
    
        prefetch_directory = "./dump"
        os.makedirs(prefetch_directory, exist_ok=True)  # 출력 디렉토리 생성
    
        self.ui.textBrowser.append("Volatility3 filescan 실행 중...")
    
        # VolatilityWorker 스레드 실행
        self.ui.textBrowser.append("Volatility 실행 중...")
        self.worker = VolatilityDWorker("windows.dumpfiles.DumpFiles", memory_dump_file)
        self.worker.update_signal.connect(self.update_text_browser)
        self.worker.finished.connect(
            lambda: self.ui.textBrowser.append("Volatility 작업이 완료되었습니다.")
        )  # 작업 완료 시 TextBrowser에 메시지 추가
        self.worker.start()

    def recover_prefetch_files(self):
        """Prefetch 파일 복구"""
        prefetch_directory = "./dumped_files"
        self.ui.textBrowser.append("Prefetch 파일 복구 중...")
        self.decompress_prefetch_files(prefetch_directory)
        self.ui.textBrowser.append(f"Prefetch 파일 복구 완료: {prefetch_directory}")

    def analyze_prefetch_files(self):
        """Prefetch 파일 분석"""
        file_path = self.ui.lineEdit_2.text()
        try:
            # .pf 파일 필터링 및 저장
            output_file = "./pf_list.txt"  # 저장할 파일 경로
            with open(file_path, "r", encoding="utf-8") as infile:
                lines = infile.readlines()

            # .pf로 끝나는 줄 필터링
            pf_lines = [line.strip() for line in lines if line.strip().endswith(".pf")]

            # 결과를 pf_list.txt에 저장
            with open(output_file, "w", encoding="utf-8") as outfile:
                outfile.write("\n".join(pf_lines))

            # TextBrowser에 필터링된 내용을 출력
            self.ui.textBrowser.append("필터링된 Prefetch 목록:")
            for pf_line in pf_lines:
                self.ui.textBrowser.append(pf_line)

            self.ui.textBrowser.append(f"Prefetch 목록 저장 완료: {output_file}")

        except Exception as e:
            self.ui.textBrowser.append(f"오류 발생: {str(e)}")
    
    def save_prefetch_list(self):
        """Prefetch 목록 선택 저장"""
        # 사용자에게 파일 선택 대화 상자 표시
        file_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "텍스트 파일 선택")
        
        if file_path:
            # 선택된 파일 경로를 lineEdit_2에 설정
            self.ui.lineEdit_2.setText(file_path)
            self.ui.textBrowser.append(f"파일 선택: {file_path}")



    # 아래는 Prefetch 관련 작업 함수들
    # 초기구현 코드 - filescan 프로세스 부분인데 UI 오류로 참조 제외시킴.
    def extract_file_list(self, memory_dump_file):
        """Extracts file list using Volatility's filescan plugin."""
        sys.argv = [
            "volatility3",
            "-f", memory_dump_file,
            "windows.filescan.FileScan"
        ]
        output_buffer = io.StringIO()
        error_buffer = io.StringIO()
        
        with redirect_stdout(output_buffer), redirect_stderr(error_buffer):  # stdout 리다이렉션
            try:
                volatility3.cli.main()
            except SystemExit:
                pass  # Volatility 종료 방지
        cli_output = output_buffer.getvalue()
        cli_error = error_buffer.getvalue()
        if cli_output:
            self.ui.textBrowser.append(cli_output)
        if cli_error:
            self.ui.textBrowser.append(cli_error)
            # Write output to a file
        with open("/fscanList.txt", "w", encoding="utf-8") as f:
            f.write(cli_output)
        self.ui.textBrowser.append("Volatility 실행 완료.\n")
        return output_buffer.getvalue()

    def find_prefetch_addresses(self, file_scan_output):
        """Finds Prefetch files from the filescan output."""
        prefetch_files = []
        for line in file_scan_output.split("\n"):
            if ".pf" in line:
                parts = line.split()
                memory_address = parts[0]
                filename = parts[-1]
                prefetch_files.append((memory_address, filename))
        return prefetch_files

    def decompress_prefetch_files(self, prefetch_directory):
        """Decompresses Prefetch files using lznt1."""
        
        current_dir = os.path.dirname(os.path.abspath(__file__))
        vol_script = os.path.join(current_dir, "vol.py")
        memory_path = os.path.join(current_dir, "/dump")
        
        for root, _, files in os.walk(memory_path):
            for file in files:
                memory_dump_file = os.path.join(root, file)
                self.worker = VolatilitypfWorker("windows.prefetch.Prefetch", memory_dump_file)
                self.worker.update_signal.connect(self.update_text_browser)
                self.worker.finished.connect(
                    lambda: self.ui.textBrowser.append("Volatility 작업이 완료되었습니다.")
                )  # 작업 완료 시 TextBrowser에 메시지 추가
                self.worker.start()
    def analyze_decompressed_files(self, prefetch_directory):
        """Analyzes decompressed Prefetch files."""
        for file in os.listdir(prefetch_directory):
            if file.endswith(".decompressed"):
                print(f"Analyzing decompressed Prefetch file: {file}")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = PrefetchAnalyzer()
    window.show()
    sys.exit(app.exec_())
