from flask import Flask, request, jsonify
import ast
import logging
import os

# Ensure log directory and file exist
log_dir = "/app/logs"
log_file = os.path.join(log_dir, "flask.log")

os.makedirs(log_dir, exist_ok=True)  # Ensure logs directory exists
os.chmod(log_dir, 0o777)  # Make sure it's writable

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(log_file, mode='a')]
)

logging.info("Logging setup complete. Flask app starting...")

# Initialize Flask app
app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    logging.info("Home route accessed")
    return jsonify({"message": "Welcome to Flask app!"})

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyzes user-supplied Python code for risky functions."""
    try:
        data = request.get_json()
        logging.info(f"Received data: {data}")

        if not data or "code" not in data:
            logging.warning("Missing 'code' in request")
            return jsonify({"error": "Missing 'code'"}), 400

        expression = data["code"]

        # Process expression safely using AST
        result = ast.literal_eval(expression)

        logging.info(f"Expression evaluated successfully: {expression} = {result}")
        return jsonify({"result": result})

    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({"error": str(e)}), 500

# Define risky functions & modules
RISKY_FUNCTIONS = {
    "exec", "eval", "compile", "open",
    "subprocess.call", "subprocess.Popen", "subprocess.run",
    "os.system", "requests.get", "socket"
}

RISKY_MODULES = {"subprocess", "os", "requests", "socket", "base64"}

class EnhancedRiskyCodeAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.risky_calls = []
        self.imports = set()

    def visit_Import(self, node):
        """Capture imported modules (e.g., import os)"""
        for alias in node.names:
            if alias.name in RISKY_MODULES:
                self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Capture 'from module import ...' statements"""
        if node.module and node.module in RISKY_MODULES:
            self.imports.add(node.module)
        self.generic_visit(node)

    def visit_Call(self, node):
        """Detect function calls, including module-based calls (e.g., subprocess.call())"""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            logging.debug(f"Direct function call detected: {func_name}")
            if func_name in RISKY_FUNCTIONS:
                self.risky_calls.append({"function": func_name})

        elif isinstance(node.func, ast.Attribute):
            module_name = self.get_module_name(node.func.value)
            func_name = node.func.attr
            full_call = f"{module_name}.{func_name}"

            logging.debug(f"Module-based function call detected: {full_call}")
            if full_call in RISKY_FUNCTIONS:
                self.risky_calls.append({"function": full_call})

        self.generic_visit(node)

    def get_module_name(self, node):
        """Recursively extract full module name (e.g., subprocess.call -> subprocess.call)"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self.get_module_name(node.value) + "." + node.attr
        return "unknown"

def analyze_python_code(code):
    """
    Parses Python code and detects risky execution patterns.
    """
    try:
        tree = ast.parse(code)
        analyzer = EnhancedRiskyCodeAnalyzer()
        analyzer.visit(tree)

        results = {"status": "valid", "details": "No risky behavior detected"}
        if analyzer.imports:
            results["imports"] = list(analyzer.imports)

        if analyzer.risky_calls:
            results["status"] = "suspicious"
            results["risky_calls"] = analyzer.risky_calls

        return results

    except SyntaxError as e:
        return {"status": "invalid", "error": str(e)}

@app.route("/scan", methods=["POST", "GET"])
def scan():
    extracted_code = None

    # 1. Extract JSON
    if request.is_json:
        json_data = request.get_json()
        if "code" in json_data:
            extracted_code = json_data["code"]

    # 2. Extract from form data
    elif "code" in request.form:
        extracted_code = request.form["code"]

    # 3. Extract from URL parameters
    elif "code" in request.args:
        extracted_code = request.args.get("code")

    # 4. Extract from raw text body
    elif request.data:
        extracted_code = request.data.decode("utf-8").strip()

    # 5. Extract from custom header
    elif "X-Python-Code" in request.headers:
        extracted_code = request.headers["X-Python-Code"]

    if not extracted_code:
        return jsonify({"status": "error", "message": "No Python code found in request"}), 400

    # Analyze the extracted code
    result = analyze_python_code(extracted_code)

    return jsonify(result), (403 if result["status"] == "suspicious" else 200)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200

if __name__ == '__main__':
    app.run(debug=False)
