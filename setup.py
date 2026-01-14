from setuptools import setup, find_packages

setup(
    name="autopyara",
    version="0.1.0",
    description="Next-Gen Automatic YARA Rule Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Mabon Ninan", # Change this
    packages=find_packages(),
    include_package_data=True, # Crucial for including the JAR
    install_requires=[
        "jpype1",
        "yara-python",
        "yaramod",
        "scikit-learn",
        "numpy",
        "ppdeep"
    ],
    python_requires='>=3.8',
)