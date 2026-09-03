from setuptools import setup, find_packages

# Note: AutoPYara requires a JRE (11+) at runtime (see autopyara/interface.py's
# PythonInterface._check_java_installed(), which raises a clear error the
# first time AutoPYara() is constructed without one). That check intentionally
# does NOT run here at install time: this package ships both an sdist and a
# wheel, so most installs never execute this file at all, and gating pip
# install on Java would be inconsistent (wheel installs would skip it anyway)
# and unnecessarily block installing the package on a machine that will only
# run it elsewhere (e.g. building a Docker image). Full functional
# correctness (a real JVM run against the built package) is instead verified
# in CI before every release — see .github/workflows/release.yml and
# RELEASING.md.

setup(
    name="autopyara",
    version="0.1.2",
    description="Next-Gen Automatic YARA Rule Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GIA MTech",
    maintainer="Mabon Ninan",
    maintainer_email="ninanmm@tamu.edu",
    url="https://github.com/Botacin-s-Lab/AutoPYaraPyPI",
    project_urls={
        "Homepage": "https://github.com/Botacin-s-Lab/AutoPYaraPyPI",
        "Documentation": "https://botacin-s-lab.github.io/AutoPYaraPyPI/",
        "Source": "https://github.com/Botacin-s-Lab/AutoPYaraPyPI",
        "Issue Tracker": "https://github.com/Botacin-s-Lab/AutoPYaraPyPI/issues",
        "Changelog": "https://github.com/Botacin-s-Lab/AutoPYaraPyPI/releases",
    },
    license="MIT",
    keywords=[
        "yara", "malware-analysis", "malware-clustering",
        "bloom-filter", "threat-intelligence", "security",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,

    entry_points={
        'console_scripts': [
            'autopyara-download=autopyara.download:download_and_extract',
        ],
    },

    install_requires=[
        "jpype1",
        "yara-python",
        "yaramod",
        "scikit-learn>=1.0",
        "numpy>=1.20,<2.0",
        "packaging>=20.0",
        "ppdeep"
    ],
    extras_require={
        "test": ["pytest"],
    },
    # 3.8 reached EOL in Oct 2024 and yara-python/yaramod/scikit-learn's
    # current releases no longer publish wheels for it (confirmed against
    # PyPI) -- CI's test matrix (.github/workflows/release.yml) only covers
    # 3.9-3.12.
    python_requires='>=3.9',
)
