class MissingKey(Exception): pass
class MissingSigner(Exception): pass
class MissingVerifier(Exception): pass

class SignatureError(Exception): pass
class RouteMissingError(Exception): pass
class RouteEndpointError(Exception): pass

class ParameterNotUnderstood(Exception): pass
class AlgorithmNotImplemented(Exception): pass
