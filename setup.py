from setuptools import setup, find_packages

setup(
    name="red-team-audit",
    version="1.0.0",
    description="Red Team Security Audit Tool for GitHub Repositories",
    author="Red Team",
    author_email="redteam@example.com",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "colorama>=0.4.4",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "redteam-audit=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)