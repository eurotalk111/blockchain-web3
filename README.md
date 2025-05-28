You can use the following endpoints after hosting ``blockchain.py`` on your local host
to test the blockchain. Take note, you have to install the following packages using ``pip install``

(copy & paste this code into your command terminal)

```pip install flask cryptography```

Then follow the steps below if you'd like to test the blockchain system.

1. Run the script with ``python blockchain.py``

2. Use endpoints like ``/wallet/new`` to create wallets and ``/transactions/new`` to create transactions

3. Mine blocks with the ``/mine`` endpoint

4. Check the chain with ``/chain``

⚠️ The endpoint ``/transactions/new`` will say **METHOD NOT ALLOWED**, please test other endpoints while I
attempt to fix the program.
