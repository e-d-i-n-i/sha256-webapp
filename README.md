# SHA-256 From Scratch Web Application 🗝️

This project demonstrates the SHA-256 cryptographic hash function implemented from scratch in Python. The backend is built using Flask, and the frontend is created with HTML, CSS, and JavaScript.

## Features

- **SHA-256 Implementation**: The core of the project is a custom implementation of the SHA-256 algorithm in Python, without relying on any external libraries.
- **Web Interface**: A simple and intuitive web interface allows users to input a message and generate its SHA-256 hash.
- **API-Driven**: The web app uses a RESTful API to communicate with the backend, where the SHA-256 hash is computed.
- **Easy Deployment**: The application is easy to deploy on any server or cloud platform supporting Python and Flask.

## Getting Started

### Prerequisites

- **Python 3.x**
- **Flask** (Install via `pip install flask`)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/e-d-i-n-i/sha256-from-scratch-webapp.git
   cd sha256-webapp
   ```

2. Set up a virtual environment and install dependencies:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   pip install -r requirements.txt
   ```

3. Run the Flask application:

   ```bash
   python app.py
   ```

4. Open `index.html` in your browser to access the web interface.

## Usage

1. Enter a message in the input field.
2. Click "Generate SHA-256 Hash" to see the computed hash displayed below.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
