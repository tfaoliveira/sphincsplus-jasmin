import re

from generic_fn import GenericFn
from task import Task


def parse_tasks(text: [str], global_params: dict[str, int]) -> [Task]:
    res: [Task] = []

    for s in text:
        fields: [str] = s.split()
        params: dict[str, int] = {}
        fn_name: str = fields[0].split(":")[-1]
        for field in fields:
            if field.startswith("p:"):
                # Split the field by ':'
                _, key, value = field.split(":")
                params[key] = int(value)

        task = Task(fn_name, params.values(), global_params)
        res.append(task)

    return res


def get_params(code: str) -> dict[str, int]:
    """
    Extracts and evaluates parameter declarations from Jasmin source code.
    The code assumes that all parameter declarations follow the format
    'param int <parameter_name> = <expression>;'
    """
    pattern = r"param\s+int\s+(\w+)\s*=\s*(.+);"
    matches = re.findall(pattern, code, re.MULTILINE)
    param_dict = dict(matches)
    res: dict[str, int] = {}
    visited: set[str] = set()

    def evaluate_expression(param_name: str):
        if param_name in visited:
            raise ValueError("Circular dependency.")

        visited.add(param_name)
        param_value = param_dict[param_name]
        res[param_name] = eval(param_value, None, res)
        visited.remove(param_name)

    for key in param_dict:
        evaluate_expression(key)

    return res


def get_generic_fn_dict(input_text: str) -> dict[str, GenericFn]:
    """
    Extracts generic function declarations from the input text and returns a dictionary
    containing information about each generic function.
    """
    res: dict[str, GenericFn] = {}

    pattern = r"([#\[\]\"=\w\s]*)\s+?fn\s+(\w+)<([^>]+)>\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    if matches := re.finditer(pattern, input_text, flags=re.MULTILINE):
        for match in matches:
            annotation, fn_name, params, args, fn_body = match.groups()

            annotation = annotation.strip()
            if "#" in annotation:
                annotation += "\n"

            generic_fn = GenericFn(annotation, fn_name, params, args, fn_body)
            res[fn_name] = generic_fn

    return res


def remove_generic_fn_text(input_text: str) -> str:
    """
    Returns the updated input text with the generic function declarations removed
    """
    res: dict[str, GenericFn] = {}

    pattern = r"([#\[\]\"=\w\s]*)\s+?fn\s+(\w+)<([^>]+)>\s*\(([^\)]+)\)([\s\S]*?)}//<>"

    matches = re.finditer(pattern, input_text, flags=re.MULTILINE)

    replacements = []

    for match in matches:
        _, fn_name, _, _, _ = match.groups()
        replacement_text = (
            f"\n\n// Place concrete instances of the {fn_name} function here"
        )
        replacements.append((match.start(), match.end(), replacement_text))

    # Sort the replacements in reverse order to ensure that replacing text doesn't affect other replacements
    replacements.sort(reverse=True)

    for start, end, replacement_text in replacements:
        input_text = input_text[:start] + replacement_text + input_text[end:]

    return input_text


def replace_generic_calls_with_concrete(
    text: str, global_params: dict[str, int]
) -> str:
    """
    Replaces generic function calls with concrete function calls based on the provided parameters.

    This function takes an input 'text' that may contain generic function calls with generic
    type parameters, e.g., 'my_function<T, U>(x, y)'. It also takes a dictionary 'global_params'
    containing concrete values for the generic type parameters. The function then replaces
    the calls to generic functions with the corresponding calls to concrete functions.
    """

    def replace_fn(match):
        fn_name, generic_params = match.groups()
        generic_params = [p.strip() for p in generic_params.split(",")]
        concrete_params: dict[str, int] = {}

        for param in generic_params:
            try:
                # Evaluate the expression using the global_params dict to get the concrete value
                concrete_params[param] = eval(param, None, global_params)
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p)) for p in generic_params]
        concrete_call = f"{fn_name}_" + "_".join(concrete_args)

        return concrete_call

    pattern = r"(\w+)<([^>]+)>"
    return re.sub(pattern, replace_fn, text)


def get_tasks(text: str, global_params: dict[str, int]) -> list[Task]:
    """
    This function also replaces generic function calls with calls to the concrete functions
    """
    tasks = set()
    generic_fn_call_pattern = r"(\w+)<([^>]+)>\(([^)]+)\);"

    def replace_fn(match) -> str:
        fn_name, generic_params, generic_args = match.groups()
        generic_params: list[str] = [p.strip() for p in generic_params.split(",")]
        concrete_params = {}

        for param in generic_params:
            try:
                # Evaluate the expression using the param_dict to get the concrete value
                concrete_params[param] = eval(param, None, global_params)
            except (NameError, TypeError, ValueError, SyntaxError):
                # If evaluation fails, use the original param as a string
                concrete_params[param] = param

        concrete_args = [str(concrete_params.get(p, p)) for p in generic_params]
        tasks.add((fn_name, tuple(concrete_args)))  # Store the task with all parameters
        return f"{fn_name}_" + "_".join(concrete_args) + f"({generic_args})"

    text = re.sub(generic_fn_call_pattern, replace_fn, text)
    return [  # We only return the tasks that can be solved right away. We look for subtasks later
        Task(fn_name, list(params), global_params)
        for fn_name, params in tasks
        if all(param.isdigit() for param in params)
    ]


def replace_parameters_in_string(text: str, replacement_dict: dict[str, int]) -> str:
    """_
    Auxiliary function to replace the parameters with their value
    """
    for key, value in replacement_dict.items():
        text = text.replace(f"{key}", str(value))
    return text


def build_concrete_fn(generic_fn: GenericFn, replacement_dict: dict[str, int]) -> str:
    """
    Build the concrete function from the generic one

    Args:
        generic_fn (GenericFn): Information about the generic function
        replacement_dict (dict[str, int]): Map containing the value of each parameter to replace in the function
    """

    tmp = replace_parameters_in_string("_".join(generic_fn.params), replacement_dict)

    if generic_fn.annotation == "":
        res = f"fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    elif "#" in generic_fn.annotation:
        res = f"{generic_fn.annotation}fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    else:
        res = f"{generic_fn.annotation} fn {generic_fn.fn_name}_{tmp}({replace_parameters_in_string(generic_fn.args, replacement_dict)})"
    res += replace_parameters_in_string(generic_fn.fn_body, replacement_dict)
    res += "}"

    return res
