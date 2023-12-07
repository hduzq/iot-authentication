from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
import pickle

def save_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    p = parameters.parameter_numbers().p
    g = parameters.parameter_numbers().g
    with open('parameters.pkl', 'wb') as f:
        pickle.dump((p, g), f)

save_parameters()