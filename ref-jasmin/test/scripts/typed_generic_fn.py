class TypedGenericFn:
    """
    Same as GenericFn but with extra information.
    E.g.: inline fn __map_e<N>[F,TYPE](reg ptr TYPE[N] a) -> reg ptr TYPE[N]
    """

    def __init__(
        self,
        annotation: str,
        fn_name: str,
        params: str,
        args: str,
        fn_body: str,
        generic_fn_names: list[str],
        generic_fn_types: list[str],
    ):
        self.annotation = annotation
        self.fn_name = fn_name
        self.params = [p.strip() for p in params.split(",")]
        self.args = args
        self.fn_body = fn_body
        self.generic_fn_names = [name.strip() for name in generic_fn_names]
        self.generic_fn_types = [type.strip() for type in generic_fn_types]

    def __repr__(self) -> str:
        return (
            f"Annotation: {self.annotation}\n"
            f"Function Name: {self.fn_name}\n"
            f"Parameters: {self.params}\n"
            f"Generic Fn Names: {self.generic_fn_names}\n"
            f"Generic Fn Types: {self.generic_fn_types}\n"
            f"Arguments: {self.args}\n"
            f"Function Body:\n{self.fn_body}\n\n"
        )
