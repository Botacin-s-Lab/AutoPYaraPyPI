import jpype
import jpype.imports
import atexit
import gc
import os
import shutil
import sys
from typing import Any
from jpype.types import *

class PythonInterface:
    _jvm_started = False
    
    # Logic to find the jar relative to this file
    PACKAGE_ROOT = os.path.dirname(os.path.abspath(__file__))

    @staticmethod
    def _check_java_installed():
        """Verifies Java is available before crashing."""
        if shutil.which("java") is None and not os.getenv("JAVA_HOME"):
            raise RuntimeError(
                "CRITICAL ERROR: Java is not installed or not found in PATH.\n"
                "AutoPYara requires a Java Runtime Environment (JRE 11+).\n"
                "Please install it (e.g., 'sudo apt install default-jre')."
            )

    @classmethod
    def _start_jvm(cls):
        if not cls._jvm_started:
            cls._check_java_installed()

            # Locate the JAR inside the package
            jar_path = os.path.join(cls.PACKAGE_ROOT, "jars", "AutoYara.jar")
            
            # Dev fallback: check env var if jar isn't inside package
            if not os.path.exists(jar_path):
                jar_path = os.getenv("AUTOPYARA_JAR", jar_path)

            if not os.path.exists(jar_path):
                 raise FileNotFoundError(f"Could not find internal component: {jar_path}")

            print(f"[*] Initializing Backend: {jar_path}")

            try:
                jpype.startJVM(
                    jpype.getDefaultJVMPath(),
                    f"-Djava.class.path={jar_path}",
                    "-Xmx14g", # Memory limit
                    convertStrings=True
                )
                cls._jvm_started = True
                atexit.register(cls._shutdown_jvm)
            except Exception as e:
                print(f"Failed to start JVM: {e}")
                raise

    @classmethod
    def _shutdown_jvm(cls):
        if cls._jvm_started and jpype.isJVMStarted():
            jpype.shutdownJVM()
            cls._jvm_started = False

    def __init__(self):
        self._start_jvm()

    def reset_memory(self):
        gc.collect()
        jpype.java.lang.System.gc()

    def convert_java_to_python(self, obj: Any) -> Any:
        """Recursive converter for Java types to Python types."""
        if obj is None: return None
        
        if hasattr(obj, 'getClass'):
            cls_name = obj.getClass().getName()
            if cls_name in ["java.util.ArrayList", "java.util.LinkedList", "java.util.Vector"]:
                return [self.convert_java_to_python(i) for i in obj]
            if cls_name in ["java.util.HashMap", "java.util.LinkedHashMap", "java.util.TreeMap"]:
                return {str(k): self.convert_java_to_python(v) for k, v in obj.items()}

        if isinstance(obj, JArray): return [self.convert_java_to_python(i) for i in obj]
        if isinstance(obj, (JBoolean, JByte, JChar, JDouble, JFloat, JInt, JLong, JShort)): return obj.value
        if isinstance(obj, JString): return str(obj)
        if isinstance(obj, dict): return {k: self.convert_java_to_python(v) for k, v in obj.items()}
        if isinstance(obj, list): return [self.convert_java_to_python(i) for i in obj]

        return obj