from setuptools import setup

setup(
    name="certificatinator",
    version="1.0.0",
    description="A tool to manage SSL certificates in certifi-style bundles",
    py_modules=["certificatinator"],
    install_requires=[
        "cryptography>=3.0.0",
    ],
    entry_points={
        "console_scripts": [
            "certificatinator=certificatinator:main",
        ],
    },
    python_requires=">=3.6",
)
