from setuptools import setup, find_packages

setup(
    name="autopyara",
    version="0.1.0",
    description="Next-Gen Automatic YARA Rule Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Mabon Ninan",
    packages=find_packages(),
    include_package_data=True,  # Crucial for including the JARs via MANIFEST.in
    
    # --- NEW: Registers the command line tool ---
    entry_points={
        'console_scripts': [
            # This allows users to type 'autopyara-download' in their terminal
            'autopyara-download=autopyara.download:download_and_extract',
        ],
    },
    # ---------------------------------------------

    install_requires=[
        "jpype1",
        "yara-python",
        "yaramod",
        # Use >= to allow older, compatible versions
        "scikit-learn>=1.0",  
        "numpy>=1.20,<2.0",   # Keeps Numba happy
        "packaging>=20.0",    # Keeps Streamlit happy
        "ppdeep"
    ],
    python_requires='>=3.8',
)