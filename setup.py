from setuptools import setup, find_packages

setup(
    name="autopyara",
    version="0.1.0",
    description="Next-Gen Automatic YARA Rule Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GIA MTech",
    packages=find_packages(),
    include_package_data=True,  
    
    # --- Restored: Registers the command line tool ---
    entry_points={
        'console_scripts': [
            'autopyara-download=autopyara.download:download_and_extract',
        ],
    },
    # ---------------------------------------------

    install_requires=[
        "jpype1",
        "yara-python",
        "yaramod",
        "scikit-learn>=1.0",  
        "numpy>=1.20,<2.0",   
        "packaging>=20.0",    
        "ppdeep"
    ],
    python_requires='>=3.8',
)

