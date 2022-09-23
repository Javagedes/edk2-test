from genericpath import isdir
import pathlib
import logging
import os
import io
import shutil
from typing import List

from os.path import join
from shutil import copyfile
from edk2toolext.environment.uefi_build import UefiBuilder
from edk2toolext.invocables.edk2_platform_build import BuildSettingsManager
from edk2toolext.invocables.edk2_setup import SetupSettingsManager, RequiredSubmodule
from edk2toolext.invocables.edk2_update import UpdateSettingsManager
from edk2toollib.utility_functions import RunPythonScript, RunCmd, RemoveTree
from edk2toollib.uefi.edk2.path_utilities import Edk2Path

class SctBuilder():
    def __init__(self, arch, uefi_path, ihv_path, sct_pkg, out_dir):
        self.sct_pkg = sct_pkg
        self.uefi = uefi_path
        self.ihv = ihv_path
        self.arch = arch
        
        #
        # Folders
        #
        self.base = out_dir
        self.framework = join(self.base, self.arch)

        self.data         = join(self.framework, "Data")
        self.dependency   = join(self.framework, "Dependency")
        self.support      = join(self.framework, "Support")
        self.test         = join(self.framework, "Test")
        self.sequence     = join(self.framework, "Sequence")
        self.report       = join(self.framework, "Report")
        self.application  = join(self.framework, "Application")
        self.proxy        = join(self.framework, "Proxy")
        self.ents_support = join(self.framework, "Ents", "Support")
        self.ents_test    = join(self.framework, "Ents", "Test")

    def MakeApp(self):
        
        if os.path.isdir(self.base):
            RemoveTree(self.base)
        
        #
        # Create Target Directory
        #
        os.makedirs(self.data)
        os.makedirs(self.dependency)
        os.makedirs(self.support)
        os.makedirs(self.test)
        os.makedirs(self.sequence)
        os.makedirs(self.report)
        os.makedirs(self.application)
        os.makedirs(self.proxy)
        os.makedirs(self.ents_support)
        os.makedirs(self.ents_test)

        #
        # Copy the SCT framework and the related application
        # Common, can be copied from self.uefi or self.ihv
        #
        path = self.uefi if self.uefi is not None else self.ihv
        self._CopyFile("SCT.efi",          path, self.framework)
        self._CopyFile("StallForKey.efi",  path, self.framework)
        self._CopyFile("InstallSct.efi",   path, self.base, rename=f'Install{self.arch}.efi')
        self._CopyFile("StandardTest.efi", path, self.support)
        self._CopyFile("TestProfile.efi",  path, self.support)
        self._CopyFile("TestRecovery.efi", path, self.support)
        self._CopyFile("TestLogging.efi",  path, self.support)
        
        self._CopyFile("SctStartup.nsh", join(self.sct_pkg, "Config", "Script"), self.base)
        self._CopyFile("Category.ini",   join(self.sct_pkg, "Config", "Data"),   self.data)
        self._CopyFile("GuidFile.txt",   join(self.sct_pkg, "Config", "Data"),   self.data)


    def AddUefiSctTests(self):
        #
        # Copy SCRT app
        #
        scrt = join(self.framework, "SCRT")
        os.makedirs(scrt)
        self._CopyFile("SCRTDRIVER.efi", self.uefi, scrt)
        self._CopyFile("SCRTAPP.efi",    self.uefi, scrt)
        self._CopyFile("SCRT.conf",      join(self.sct_pkg, "Config", "Data"), scrt)

        #
        # Copy ENTS binary
        #
        self._CopyFile("SerialMonitor.efi", self.uefi, self.ents_support)
        self._CopyFile("ManagedNetworkMonitor.efi", self.uefi, self.ents_support)
        self._CopyFile("IP4NetworkMonitor.efi", self.uefi, self.ents_support)
        self._CopyFile("Eftp.efi", self.uefi, self.ents_support)

        #
        # Copy tests
        #
        for file in filter(lambda f: f.endswith("Test.efi"), os.listdir(self.uefi)):
            # Edge cases
            if file == "StandardTest.efi":
                continue

            if file.endswith("ENTSTest.efi"):
                self._CopyFile(file, self.uefi, self.ents_test)
            else:
                self._CopyFile(file, self.uefi, self.test)
        
        #
        # Copy Test dependencies
        #
        for file in filter(lambda f: "_" in f, os.listdir(self.uefi)):
            
            # Edge cases
            if file.endswith("ENTSTest.efi") or file == "TOOLS_DEF.X64":
                continue

            test, dep_name = file.split("_")
            dep_folder = join(self.dependency, f'{test}BBTest')
            
            # If folder exists, then Ihv added created dependencies
            if not os.path.isdir(dep_folder):
                os.makedirs(dep_folder)

            self._CopyFile(file, self.uefi, dep_folder, rename = dep_name)

    def AddIhvSctTests(self):
        #
        # Copy tests
        #
        for file in filter(lambda f: f.endswith("Test.efi"), os.listdir(self.ihv)):
            # Edge cases
            if file == "StandardTest.efi":
                continue

            self._CopyFile(file, self.ihv, self.test)

    def _CopyFile(self, file, in_path, out_path, rename = None):
        if rename is None:
            rename = file
        copyfile(join(in_path, file), join(out_path, rename))


class Common():
    PackagesSupported = ("SctPkg",)
    ArchSupported = ("X64 IA32")
    TargetsSupported = ("DEBUG", "RELEASE")
    Scopes = ('edk2-build', 'edk2-test')
    WorkspaceRoot = str(pathlib.Path(__file__).parent.parent.parent)
    PackagesPath = ("EDK2", "uefi-sct")
    Name = "SctPkg"


class SettingsManager(UpdateSettingsManager, SetupSettingsManager):
    def GetPackagesSupported(self):
        return Common.PackagesSupported

    def GetArchitecturesSupported(self):
        return Common.ArchSupported

    def GetTargetsSupported(self):
        return Common.TargetsSupported

    def GetRequiredSubmodules(self):
        ''' return iterable containing RequiredSubmodule objects.
        If no RequiredSubmodules return an empty iterable
        '''
        rs = []

        # To avoid maintenance of this file for every new submodule
        # lets just parse the .gitmodules and add each if not already in list.
        # The GetRequiredSubmodules is designed to allow a build to optimize
        # the desired submodules but it isn't necessary for this repository.
        result = io.StringIO()
        ret = RunCmd("git", "config --file .gitmodules --get-regexp path",
                     workingdir=self.GetWorkspaceRoot(), outstream=result)
        # Cmd output is expected to look like:
        # submodule.CryptoPkg/Library/OpensslLib/openssl.path CryptoPkg/Library/OpensslLib/openssl
        # submodule.SoftFloat.path ArmPkg/Library/ArmSoftFloatLib/berkeley-softfloat-3
        if ret == 0:
            for line in result.getvalue().splitlines():
                _, _, path = line.partition(" ")
                if path is not None:
                    if path not in [x.path for x in rs]:
                        # add it with recursive since we don't know
                        rs.append(RequiredSubmodule(path, True))
        return rs

    def SetArchitectures(self, list_of_requested_architectures):
        unsupported = set(list_of_requested_architectures) - \
            set(self.GetArchitecturesSupported())

        if len(unsupported) > 0:
            errorString = (
                "Unsupported Architecture Requested: " + " ".join(unsupported)
            )
            logging.critical(errorString)
            raise Exception(errorString)

    def GetWorkspaceRoot(self):
        return Common.WorkspaceRoot

    def GetActiveScopes(self):
        return Common.Scopes

    def GetName(self):
        return Common.Name

    def GetPackagesPath(self):
        return Common.PackagesPath


class Builder(UefiBuilder, BuildSettingsManager):
    def __init__(self):
        UefiBuilder.__init__(self)

    def GetWorkspaceRoot(self):
        return Common.WorkspaceRoot

    def GetPackagesPath(self):
        return Common.PackagesPath

    def GetActiveScopes(self):
        return Common.Scopes

    def GetName(self):
        return Common.Name

    def GetLoggingLevel(self, loggerType):
        return logging.INFO
    
    def AddCommandLineOptions(self, parserObj):
        parserObj.add_argument("--IHVONLY", "--ihvonly", "--IhvOnly", dest="IHVONLY",
                               action='store_true', default=False, help="Build only IHV tests")
        parserObj.add_argument("--UEFIONLY", "--uefionly", "--UefiOnly", dest="UEFIONLY",
                               action='store_true', default=False, help="Build only UEFI tests")

    def RetrieveCommandLineOptions(self, args):
        self.BuildIhv = True
        self.BuildUefi = True

        if args.IHVONLY and args.UEFIONLY:
            logging.error("Cannot set IHVOnly and UEFIOnly...")
            raise ValueError
        
        if args.IHVONLY:
            self.BuildUefi = False
        
        if args.UEFIONLY:
            self.BuildIhv = False

    def SetPlatformEnv(self):
        logging.debug("Setting Platform Environment Variables")
        self.env.SetValue("ACTIVE_PLATFORM", "SctPkg/UEFI/UEFI_SCT.dsc", "Platform Hardcoded", overridable=True)
        # self.env.SetValue("ACTIVE_PLATFORM", "SctPkg/UEFI/IHV_SCT.dsc", "Platform Hardcoded")
        # BLD_*_
        self.env.SetValue("TARGET_ARCH", "X64", "Platform Hardcoded")
        logging.debug("Platform Environment Variables Set")
        return 0
    
    def PlatformPreBuild(self):
        tool_chain = self.env.GetValue("TOOL_CHAIN_TAG")
        tools_path = self.env.GetValue("EDK_TOOLS_PATH")
        ws = self.env.GetValue("WORKSPACE")
        genbin_edk2_src = os.path.join(tools_path, "Source", "C", "GenBin")
        genbin_sct_src = os.path.join(ws, "uefi-sct", "SctPkg", "Tools", "Source", "GenBin")
        win32_bin_path = os.path.join(tools_path, "Bin", "Win32")
        
        if os.path.isdir(win32_bin_path): # add or linux_path later
            logging.info("BaseTools already compiled.")
        # Need to build build tools via VS
        elif tool_chain.startswith("VS"):
            logging.info("Preparing to compile BaseTools")
            
            shutil.copytree(genbin_sct_src, genbin_edk2_src)

            # Update Makefile for building BaseTools to also build Genbin
            makefile = os.path.join(tools_path, "Source", "C", "Makefile")
            with open(makefile, 'r+') as f:
                lines = f.readlines()
                for index, line in enumerate(lines):
                    if "APPLICATIONS =" in line:
                        lines.insert(index+1, "  GenBin \\\n")
                        break
                
                f.seek(0)
                f.writelines(lines)

            # Actually compile the BuildTools
            logging.info("Compiling BuildTools")
            RunPythonScript(os.path.join(tools_path, "Edk2ToolsBuild.py"), f'-t {tool_chain}')
            logging.info("BuildTools compiled.")

            # Undo the Makefile update since it changes a submodule
            with open(makefile, 'r+') as f:
                lines = f.readlines()
                lines.remove("  GenBin \\\n")
                f.seek(0)
                f.truncate()
                f.writelines(lines)
            
            # Remove GenBin Source since it changes a submodule
            RemoveTree(genbin_edk2_src)
            
        else:
            logging.error("SctBuild.py currently only supports Building with Windows!")
            return 1

        return 0

    def Build(self):
        # Build UEFI tests 
        if self.BuildUefi:
            self.env.SetValue("ACTIVE_PLATFORM", "SctPkg/UEFI/UEFI_SCT.dsc", "Platform Hardcoded", overridable=True)
            ret = super().Build()
            if ret != 0:
                logging.error("Failed to build UEFI Tests")
                return ret
        
        # Build IHV tests
        if self.BuildIhv:
            self.env.SetValue("ACTIVE_PLATFORM", "SctPkg/UEFI/IHV_SCT.dsc", "", overridable=True)
            ret = super().Build()
            if ret != 0:
                logging.error("Failed to build IHV Tests")
                return ret

        return 0
    
    def PlatformPostBuild(self):
        logging.info("Generating SCT Application")
        edk2path = Edk2Path(self.ws, self.GetPackagesPath())
        
        ws = self.env.GetValue("WORKSPACE")
        target = self.env.GetValue("TARGET")
        toolchain = self.env.GetValue("TOOL_CHAIN_TAG")
        arch = "X64"
        
        sct_pkg = edk2path.GetAbsolutePathOnThisSystemFromEdk2RelativePath("SctPkg")
        uefi_path = os.path.join(ws, "Build", "UefiSct", f'{target}_{toolchain}', arch) if self.BuildUefi else None
        ihv_path = os.path.join(ws, "Build", "IhvSct", f'{target}_{toolchain}', arch) if self.BuildIhv else None
        out_dir = os.path.join(ws, "Build", f'SctPackage{arch}')

        if isdir(out_dir):
            RemoveTree(out_dir)
        
        builder = SctBuilder(arch, uefi_path, ihv_path, sct_pkg, out_dir)
        
        builder.MakeApp()
        if self.BuildUefi:
            builder.AddUefiSctTests()
        if self.BuildIhv:
            builder.AddIhvSctTests()

        from pefile import PE
        from edk2toolext.image_validation import set_nx_compat_flag

        for file in _walk_directory_for_extension(['.efi'], out_dir):
            pe = PE(file)
            set_nx_compat_flag(pe)
            os.remove(file)
            pe.write(file)

        return 0

if __name__ == "__main__":
    import argparse
    import sys
    from edk2toolext.invocables.edk2_update import Edk2Update
    from edk2toolext.invocables.edk2_setup import Edk2PlatformSetup
    from edk2toolext.invocables.edk2_platform_build import Edk2PlatformBuild
    print("Invoking Stuart")
    print("     ) _     _")
    print("    ( (^)-~-(^)")
    print("__,-.\_( 0 0 )__,-.___")
    print("  'W'   \   /   'W'")
    print("         >o<")
    SCRIPT_PATH = os.path.relpath(__file__)
    parser = argparse.ArgumentParser(add_help=False)
    parse_group = parser.add_mutually_exclusive_group()
    parse_group.add_argument("--update", "--UPDATE",
                             action='store_true', help="Invokes stuart_update")
    parse_group.add_argument("--setup", "--SETUP",
                             action='store_true', help="Invokes stuart_setup")
    args, remaining = parser.parse_known_args()
    new_args = ["stuart", "-c", SCRIPT_PATH]
    new_args = new_args + remaining
    sys.argv = new_args
    if args.setup:
        print("Running stuart_setup -c " + SCRIPT_PATH)
        Edk2PlatformSetup().Invoke()
    elif args.update:
        print("Running stuart_update -c " + SCRIPT_PATH)
        Edk2Update().Invoke()
    else:
        print("Running stuart_build -c " + SCRIPT_PATH)
        Edk2PlatformBuild().Invoke()

def _walk_directory_for_extension(extensionlist: List[str], directory: os.PathLike,
                                  ignorelist: List[str] = None) -> List[os.PathLike]:
    ''' Walks a file directory recursively for all items ending in certain extension
        @extensionlist: List[str] list of file extensions
        @directory: Path - absolute path to directory to start looking
        @ignorelist: List[str] or None.  optional - default is None: a list of case insensitive filenames to ignore
        @returns a List of file paths to matching files
    '''
    if not isinstance(extensionlist, list):
        logging.critical("Expected list but got " +
                         str(type(extensionlist)))
        raise TypeError("extensionlist must be a list")

    if directory is None:
        logging.critical("No directory given")
        raise TypeError("directory is None")

    if not os.path.isabs(directory):
        logging.critical("Directory not abs path")
        raise ValueError("directory is not an absolute path")

    if not os.path.isdir(directory):
        logging.critical("Invalid find directory to walk")
        raise ValueError("directory is not a valid directory path")

    if ignorelist is not None:
        if not isinstance(ignorelist, list):
            logging.critical("Expected list but got " +
                             str(type(ignorelist)))
            raise TypeError("ignorelist must be a list")

        ignorelist_lower = list()
        for item in ignorelist:
            ignorelist_lower.append(item.lower())

    extensionlist_lower = list()
    for item in extensionlist:
        extensionlist_lower.append(item.lower())

    returnlist = list()
    for Root, Dirs, Files in os.walk(directory):
        for File in Files:
            for Extension in extensionlist_lower:
                if File.lower().endswith(Extension):
                    ignoreIt = False
                    if (ignorelist is not None):
                        for c in ignorelist_lower:
                            if (File.lower().startswith(c)):
                                ignoreIt = True
                                break
                    if not ignoreIt:
                        returnlist.append(os.path.join(Root, File))

    return returnlist