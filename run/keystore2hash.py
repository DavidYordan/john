
import json
import sys
import time
import traceback

def process_presale_wallet(filename, data):
    try:
        bkp = data["bkp"]
    except KeyError:
        sys.stdout.write("%s: presale wallet is missing 'bkp' field, this is unsupported!\n" % filename)
        return

    try:
        encseed = data["encseed"]
        ethaddr = data["ethaddr"]
    except KeyError:
        sys.stdout.write("%s: presale wallet is missing necessary fields!\n" % filename)
        return

    with open(f'{int(time.time())}.txt', 'w') as f:
        f.write(f'$ethereum$w*{encseed}*{ethaddr}*{bkp[:32]}')

def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read().decode("utf-8")

    try:
        data = json.loads(data)
        try:
            crypto = data["crypto"]
        except KeyError:
            try:
                crypto = data["Crypto"]
            except:
                process_presale_wallet(filename, data)
                return
        cipher = crypto["cipher"]
        if cipher != "aes-128-ctr":
            sys.stdout.write("%s: unexpected cipher '%s' found\n" % (filename, cipher))
            return -2
        kdf = crypto["kdf"]
        ciphertext = crypto["ciphertext"]
        mac = crypto["mac"]
        if kdf == "scrypt":
            kdfparams = crypto["kdfparams"]
            n = kdfparams["n"]
            r = kdfparams["r"]
            p = kdfparams["p"]
            salt = kdfparams["salt"]
            with open(f'{int(time.time())}.txt', 'w') as f:
                f.write(f'$ethereum$s*{n}*{r}*{p}*{salt}*{ciphertext}*{mac}')
        elif kdf == "pbkdf2":
            kdfparams = crypto["kdfparams"]
            n = kdfparams["c"]
            prf = kdfparams["prf"]
            if prf != 'hmac-sha256':
                sys.stdout.write("%s: unexpected prf '%s' found\n" % (filename, prf))
                return
            salt = kdfparams["salt"]
            with open(f'{int(time.time())}.txt', 'w') as f:
                f.write(f'$ethereum$p*{n}*{salt}*{ciphertext}*{mac}')
        else:
            assert 0
    except:
        sys.stdout.write("%s: json parsing failed\n" % filename)
        traceback.print_exc()
        return -1

    f.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: %s [Ethereum Wallet files (Geth/Mist/MyEtherWallet)]\n" % sys.argv[0])
        sys.exit(1)

    process_file(sys.argv[1])
