# Copyright (C) 2024 The MIO-KITCHEN-SOURCE Project
#
# Licensed under the GNU AFFERO GENERAL PUBLIC LICENSE, Version 3.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.gnu.org/licenses/agpl-3.0.en.html#license-text
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
import logging

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class MagiskPatch:
    def __init__(self, boot_img, Magisk_dir, magiskboot, local, IS64BIT=True, KEEPVERITY=False, KEEPFORCEENCRYPT=False,
                 RECOVERYMODE=False, MAGISAPK=None, PATCH_ARCH=None):
        self.output = None
        self.SKIPBACKUP = ''
        self.SKIPSTUB = ''
        self.SKIP64 = ''
        self.SKIP32 = ''
        self.SHA1 = None
        self.init = 'init'
        self.STATUS = None
        self.MAGISKAPK = MAGISAPK
        self.CHROMEOS = None
        self.custom = False
        self.IS64BIT = IS64BIT
        self.PATCH_ARCH = PATCH_ARCH
        self.KEEPVERITY = KEEPVERITY
        self.KEEPFORCEENCRYPT = KEEPFORCEENCRYPT
        self.RECOVERYMODE = RECOVERYMODE
        self.Magisk_dir = Magisk_dir
        self.magiskboot = magiskboot
        self.boot_img = boot_img
        self.local = local

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def auto_patch(self):
        logging.info("Magisk Boot Patcher By ColdWindScholar (3590361911@qq.com)")

        if self.boot_img == os.path.join(self.local, 'new-boot.img'):
            logging.warning(f"Cannot be named after the generated file name. Please Rename {self.boot_img}")
            return 1
        
        if not os.path.exists(self.boot_img) or not os.path.exists(self.magiskboot + (".exe" if os.name == 'nt' else '')):
            logging.error("Cannot Found Boot.img or Not Support Your Device")
            return 1

        real_cwd = os.getcwd()
        os.chdir(self.local)
        
        try:
            if self.MAGISKAPK:
                self.extract_magisk()
            self.unpack()
            self.check()
            self.patch()
            self.patch_kernel()
            self.repack()
            self.cleanup()
        finally:
            os.chdir(real_cwd)

    def exec(self, *args, out=0):
        full = [self.magiskboot, *args]
        conf = subprocess.CREATE_NO_WINDOW if os.name != 'posix' else 0
        try:
            ret = subprocess.Popen(full, shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, creationflags=conf)
            for line in iter(ret.stdout.readline, b""):
                if out == 0:
                    logging.info(line.decode("utf-8", "ignore").strip())
            ret.wait()
            if ret.returncode != 0:
                raise subprocess.CalledProcessError(ret.returncode, full)
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {e.cmd} with return code {e.returncode}")
            return e.returncode

        return ret.returncode

    def unpack(self):
        ret = self.exec('unpack', self.boot_img)
        if ret == 1:
            logging.error('Unsupported/Unknown image format')
            sys.exit(1)
        elif ret == 2:
            logging.error('ChromeOS boot image detected. ChromeOS not supported yet.')
            self.CHROMEOS = True
            sys.exit(1)
        elif ret != 0:
            logging.error('Unable to unpack boot image')
            sys.exit(1)
        
        if os.path.exists(os.path.join(self.local, 'recovery_dtbo')):
            self.RECOVERYMODE = True

    def check(self):
        logging.info('- Checking ramdisk status')
        self.STATUS = self.exec('cpio', 'ramdisk.cpio', 'test') if os.path.exists(os.path.join(self.local, 'ramdisk.cpio')) else 0
        
        if (self.STATUS & 3) == 0:
            logging.info("- Stock boot image detected")
            self.SHA1 = self.sha1(self.boot_img)
            shutil.copyfile(self.boot_img, os.path.join(self.local, 'stock_boot.img'))
            if os.path.exists(os.path.join(self.local, 'ramdisk.cpio')):
                shutil.copyfile(os.path.join(self.local, 'ramdisk.cpio'), os.path.join(self.local, 'ramdisk.cpio.orig'))
            else:
                self.SKIPBACKUP = '#'
        elif (self.STATUS & 3) == 1:
            logging.info("- Magisk patched boot image detected")
            if not self.SHA1:
                self.SHA1 = self.sha1(os.path.join(self.local, 'ramdisk.cpio'))
            self.exec('cpio', 'ramdisk.cpio', 'restore')
            shutil.copyfile(os.path.join(self.local, 'ramdisk.cpio'), os.path.join(self.local, 'ramdisk.cpio.orig'))
            self.remove(os.path.join(self.local, 'stock_boot.img'))
        elif (self.STATUS & 3) == 2:
            logging.error("Boot image patched by unsupported programs. Please restore back to stock boot image")
            sys.exit(1)

        if not (self.STATUS & 4) == 0:
            self.init = 'init.real'

    def patch(self):
        logging.info("- Patching ramdisk")
        config_path = os.path.join(self.local, 'config')
        with open(config_path, 'w', encoding='utf-8', newline='\n') as config:
            config.write(f'KEEPVERITY={str(self.KEEPVERITY).lower()}\n')
            config.write(f'KEEPFORCEENCRYPT={str(self.KEEPFORCEENCRYPT).lower()}\n')
            config.write(f'RECOVERYMODE={str(self.RECOVERYMODE).lower()}\n')
            if self.SHA1:
                config.write(f'SHA1={self.SHA1}')

        self.SKIP64 = '' if self.IS64BIT else '#'
        self.SKIP32 = '' if os.path.exists(os.path.join(self.Magisk_dir, "magisk32")) else '#'
        self.SKIPSTUB = '' if os.path.exists(os.path.join(self.Magisk_dir, "stub.apk")) else '#'

        self.exec('cpio', 'ramdisk.cpio',
                  f"add 0750 {self.init} {os.path.join(self.Magisk_dir, 'magiskinit')}",
                  "mkdir 0750 overlay.d",
                  "mkdir 0750 overlay.d/sbin",
                  f"{self.SKIP32} add 0644 overlay.d/sbin/magisk32.xz magisk32.xz",
                  f"{self.SKIP64} add 0644 overlay.d/sbin/magisk64.xz magisk64.xz",
                  f"{self.SKIPSTUB} add 0644 overlay.d/sbin/stub.xz stub.xz",
                  'patch',
                  f"{self.SKIPBACKUP} backup ramdisk.cpio.orig",
                  "mkdir 000 .backup",
                  "add 000 .backup/.magisk config")

        for w in ['ramdisk.cpio.orig', 'config', 'magisk32.xz', 'magisk64.xz']:
            self.remove(os.path.join(self.local, w))

    def remove(self, file_):
        file_path = os.path.join(self.local, file_)
        if os.path.exists(file_path):
            if os.path.isdir(file_path):
                shutil.rmtree(file_path)
            elif os.path.isfile(file_path):
                os.remove(file_path)

    def patch_kernel(self):
        if os.path.exists(os.path.join(self.local, 'kernel')):
            self.exec('hexpatch', 'kernel',
                      '49010054011440B93FA00F71E9000054010840B93FA00F7189000054001840B91FA00F7188010054',
                      'A1020054011440B93FA00F7140020054010840B93FA00F71E0010054001840B91FA00F7181010054')

    def repack(self):
        logging.info("- Repacking boot image")
        if self.exec('repack', self.boot_img) != 0:
            logging.error("Unable to repack boot image")

    def extract_magisk(self):
        custom = os.path.join(self.local, 'custom')
        if os.path.exists(custom):
            shutil.rmtree(custom)
        
        if not os.path.exists(self.MAGISKAPK):
            logging.error(f"We cannot Found {self.MAGISKAPK}, Please Check path!!!")
            logging.info("Using default binary to patch!")
            return
        if not zipfile.is_zipfile(self.MAGISKAPK):
            logging.error(f"{self.MAGISKAPK} is not a valid APK file!!!")
            return
        else:
            with zipfile.ZipFile(self.MAGISKAPK) as ma:
                namelist = ma.namelist()
                arch = [i.split('/')[1].strip() for i in namelist if i.startswith('lib') and i.endswith('libmagiskboot.so')]
                # Рекомендуется использовать перечисление/выбор пользователя для выбора архитектуры
                self.Magisk_dir = custom

    def cleanup(self):
        logging.info("Cleaning up...")
        if self.custom:
            shutil.rmtree(self.Magisk_dir)
        for w in ['kernel', 'kernel_dtb', 'ramdisk.cpio', 'stub.xz', 'stock_boot.img', 'dtb', 'extra']:
            if os.path.exists(os.path.join(self.local, w)):
                self.remove(os.path.join(self.local, w))
        self.output = os.path.join(self.local, 'new-boot.img')

    @staticmethod
    def sha1(file_path):
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                return hashlib.sha1(f.read()).hexdigest()
        return ''
