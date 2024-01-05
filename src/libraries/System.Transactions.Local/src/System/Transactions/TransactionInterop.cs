// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Transactions.DtcProxyShim;
using System.Transactions.DtcProxyShim.DtcInterfaces;
using System.Transactions.Oletx;

namespace System.Transactions
{
    public static class TransactionInterop
    {
        internal static OletxTransaction ConvertToOletxTransaction(Transaction transaction)
        {
            ArgumentNullException.ThrowIfNull(transaction);

            ObjectDisposedException.ThrowIf(transaction.Disposed, transaction);

            if (transaction._complete)
            {
                throw TransactionException.CreateTransactionCompletedException(transaction.DistributedTxId);
            }

            OletxTransaction? oletxTx = transaction.Promote();
            Debug.Assert(oletxTx != null, "transaction.Promote returned null instead of throwing.");

            return oletxTx;
        }

        /// <summary>
        /// This is the PromoterType value that indicates that the transaction is promoting to MSDTC.
        ///
        /// If using the variation of Transaction.EnlistPromotableSinglePhase that takes a PromoterType and the
        /// ITransactionPromoter being used promotes to MSDTC, then this is the value that should be
        /// specified for the PromoterType parameter to EnlistPromotableSinglePhase.
        ///
        /// If using the variation of Transaction.EnlistPromotableSinglePhase that assumes promotion to MSDTC and
        /// it that returns false, the caller can compare this value with Transaction.PromoterType to
        /// verify that the transaction promoted, or will promote, to MSDTC. If the Transaction.PromoterType
        /// matches this value, then the caller can continue with its enlistment with MSDTC. But if it
        /// does not match, the caller will not be able to enlist with MSDTC.
        /// </summary>
        public static readonly Guid PromoterTypeDtc = new Guid("14229753-FFE1-428D-82B7-DF73045CB8DA");

        public static byte[] GetExportCookie(Transaction transaction, byte[] whereabouts)
        {
            ArgumentNullException.ThrowIfNull(transaction);
            ArgumentNullException.ThrowIfNull(whereabouts);

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetExportCookie)}");
            }

            byte[] cookie;

            // Copy the whereabouts so that it cannot be modified later.
            var whereaboutsCopy = new byte[whereabouts.Length];
            Buffer.BlockCopy(whereabouts, 0, whereaboutsCopy, 0, whereabouts.Length);

            // First, make sure we are working with an OletxTransaction.
            OletxTransaction oletxTx = ConvertToOletxTransaction(transaction);

            try
            {
                oletxTx.RealOletxTransaction.TransactionShim.Export(whereabouts, out cookie);
            }
            catch (COMException comException)
            {
                OletxTransactionManager.ProxyException(comException);

                // We are unsure of what the exception may mean.  It is possible that
                // we could get E_FAIL when trying to contact a transaction manager that is
                // being blocked by a fire wall.  On the other hand we may get a COMException
                // based on bad data.  The more common situation is that the data is fine
                // (since it is generated by Microsoft code) and the problem is with
                // communication.  So in this case we default for unknown exceptions to
                // assume that the problem is with communication.
                throw TransactionManagerCommunicationException.Create(null, comException);
            }

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetExportCookie)}");
            }

            return cookie;
        }

        public static Transaction GetTransactionFromExportCookie(byte[] cookie)
        {
            ArgumentNullException.ThrowIfNull(cookie);

            if (cookie.Length < 32)
            {
                throw new ArgumentException(SR.InvalidArgument, nameof(cookie));
            }

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransactionFromExportCookie)}");
            }

            var cookieCopy = new byte[cookie.Length];
            Buffer.BlockCopy(cookie, 0, cookieCopy, 0, cookie.Length);
            cookie = cookieCopy;

            Transaction? transaction;
            TransactionShim? transactionShim = null;
            Guid txIdentifier = Guid.Empty;
            OletxTransactionIsolationLevel oletxIsoLevel = OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE;
            OutcomeEnlistment? outcomeEnlistment;
            OletxTransaction? oleTx;

            // Extract the transaction guid from the propagation token to see if we already have a
            // transaction object for the transaction.
            // In a cookie, the transaction guid is preceded by a signature guid.
            var txId = new Guid(cookie.AsSpan(16, 16));

            // First check to see if there is a promoted LTM transaction with the same ID.  If there
            // is, just return that.
            transaction = TransactionManager.FindPromotedTransaction(txId);
            if (transaction != null)
            {
                if (etwLog.IsEnabled())
                {
                    etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, "TransactionInterop.GetTransactionFromExportCookie");
                }

                return transaction;
            }

            // We need to create a new transaction
            RealOletxTransaction? realTx = null;
            OletxTransactionManager oletxTm = TransactionManager.DistributedTransactionManager;

            oletxTm.DtcTransactionManagerLock.AcquireReaderLock(-1);
            try
            {
                outcomeEnlistment = new OutcomeEnlistment();
                oletxTm.DtcTransactionManager.ProxyShimFactory.Import(cookie, outcomeEnlistment, out txIdentifier, out oletxIsoLevel, out transactionShim);
            }
            catch (COMException comException)
            {
                OletxTransactionManager.ProxyException(comException);

                // We are unsure of what the exception may mean.  It is possible that
                // we could get E_FAIL when trying to contact a transaction manager that is
                // being blocked by a fire wall.  On the other hand we may get a COMException
                // based on bad data.  The more common situation is that the data is fine
                // (since it is generated by Microsoft code) and the problem is with
                // communication.  So in this case we default for unknown exceptions to
                // assume that the problem is with communication.
                throw TransactionManagerCommunicationException.Create(SR.TraceSourceOletx, comException);
            }
            finally
            {
                oletxTm.DtcTransactionManagerLock.ReleaseReaderLock();
            }

            // We need to create a new RealOletxTransaction.
            realTx = new RealOletxTransaction(
                oletxTm,
                transactionShim,
                outcomeEnlistment,
                txIdentifier,
                oletxIsoLevel);

            // Now create the associated OletxTransaction.
            oleTx = new OletxTransaction(realTx);

            // If a transaction is found then FindOrCreate will Dispose the oletx
            // created.
            transaction = TransactionManager.FindOrCreatePromotedTransaction(txId, oleTx);

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransactionFromExportCookie)}");
            }

            return transaction;
        }

        public static byte[] GetTransmitterPropagationToken(Transaction transaction)
        {
            ArgumentNullException.ThrowIfNull(transaction);

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransmitterPropagationToken)}");
            }

            // First, make sure we are working with an OletxTransaction.
            OletxTransaction oletxTx = ConvertToOletxTransaction(transaction);

            byte[] token = GetTransmitterPropagationToken(oletxTx);

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransmitterPropagationToken)}");
            }

            return token;
        }

        internal static byte[] GetTransmitterPropagationToken(OletxTransaction oletxTx)
        {
            byte[]? propagationToken = null;

            try
            {
                propagationToken = oletxTx.RealOletxTransaction.TransactionShim.GetPropagationToken();
            }
            catch (COMException comException)
            {
                OletxTransactionManager.ProxyException(comException);
                throw;
            }

            return propagationToken;
        }

        public static Transaction GetTransactionFromTransmitterPropagationToken(byte[] propagationToken)
        {
            ArgumentNullException.ThrowIfNull(propagationToken);

            if (propagationToken.Length < 24)
            {
                throw new ArgumentException(SR.InvalidArgument, nameof(propagationToken));
            }

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
            }

            // Extract the transaction guid from the propagation token to see if we already have a
            // transaction object for the transaction.
            // In a propagation token, the transaction guid is preceded by two version DWORDs.
            var txId = new Guid(propagationToken.AsSpan(8, 16));

            // First check to see if there is a promoted LTM transaction with the same ID.  If there is, just return that.
            Transaction? tx = TransactionManager.FindPromotedTransaction(txId);
            if (null != tx)
            {
                if (etwLog.IsEnabled())
                {
                    etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
                }

                return tx;
            }

            OletxTransaction dTx = GetOletxTransactionFromTransmitterPropagationToken(propagationToken);

            // If a transaction is found then FindOrCreate will Dispose the distributed transaction created.
            Transaction returnValue = TransactionManager.FindOrCreatePromotedTransaction(txId, dTx);

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, "TransactionInterop.GetTransactionFromTransmitterPropagationToken");
            }
            return returnValue;
        }

        public static IDtcTransaction GetDtcTransaction(Transaction transaction)
        {
            ArgumentNullException.ThrowIfNull(transaction);

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetDtcTransaction)}");
            }

            IDtcTransaction? transactionComObject;

            // First, make sure we are working with an OletxTransaction.
            OletxTransaction oletxTx = ConvertToOletxTransaction(transaction);

            try
            {
                oletxTx.RealOletxTransaction.TransactionShim.GetITransactionNative(out ITransaction transactionNative);

                ComWrappers.TryGetComInstance(transactionNative, out IntPtr transactionNativePtr);

                transactionComObject = (IDtcTransaction)Marshal.GetObjectForIUnknown(transactionNativePtr);
                Marshal.SetComObjectData(transactionComObject, typeof(ITransaction), transactionNative);

                Marshal.Release(transactionNativePtr);
            }
            catch (COMException comException)
            {
                OletxTransactionManager.ProxyException(comException);
                throw;
            }

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetDtcTransaction)}");
            }

            return transactionComObject;
        }

        internal static IDtcTransaction GetDtcTransaction(ITransaction transaction)
        {
            ComWrappers.TryGetComInstance(transaction, out IntPtr transactionNativePtr);

            var transactionNative = (IDtcTransaction)Marshal.GetObjectForIUnknown(transactionNativePtr);
            Marshal.SetComObjectData(transactionNative, typeof(ITransaction), transaction);

            Marshal.Release(transactionNativePtr);
            return transactionNative;
        }

        public static Transaction GetTransactionFromDtcTransaction(IDtcTransaction transactionNative)
        {
            ArgumentNullException.ThrowIfNull(transactionNative, nameof(transactionNative));

            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransactionFromDtcTransaction)}");
            }

            Transaction? transaction = null;
            bool tooLate = false;
            TransactionShim? transactionShim = null;
            Guid txIdentifier = Guid.Empty;
            OletxTransactionIsolationLevel oletxIsoLevel = OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE;
            OutcomeEnlistment? outcomeEnlistment = null;
            RealOletxTransaction? realTx = null;
            OletxTransaction? oleTx = null;

            ITransaction myTransactionNative = GetITransactionFromIDtcTransaction(transactionNative);

            // Let's get the guid of the transaction from the proxy to see if we already have an object.
            OletxXactTransInfo xactInfo;
            try
            {
                myTransactionNative.GetTransactionInfo(out xactInfo);
            }
            catch (COMException ex) when (ex.ErrorCode == OletxHelper.XACT_E_NOTRANSACTION)
            {
                // If we get here, the transaction has appraently already been committed or aborted.  Allow creation of the
                // OletxTransaction, but it will be marked with a status of InDoubt and attempts to get its Identifier
                // property will result in a TransactionException.
                tooLate = true;
                xactInfo.Uow = Guid.Empty;
            }

            OletxTransactionManager oletxTm = TransactionManager.DistributedTransactionManager;
            if (!tooLate)
            {
                // First check to see if there is a promoted LTM transaction with the same ID.  If there
                // is, just return that.
                transaction = TransactionManager.FindPromotedTransaction(xactInfo.Uow);
                if (transaction != null)
                {
                    if (etwLog.IsEnabled())
                    {
                        etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransactionFromDtcTransaction)}");
                    }

                    return transaction;
                }

                // We need to create a new RealOletxTransaction...
                oletxTm.DtcTransactionManagerLock.AcquireReaderLock(-1);
                try
                {
                    outcomeEnlistment = new OutcomeEnlistment();
                    oletxTm.DtcTransactionManager.ProxyShimFactory.CreateTransactionShim(
                        transactionNative,
                        outcomeEnlistment,
                        out txIdentifier,
                        out oletxIsoLevel,
                        out transactionShim);
                }
                catch (COMException comException)
                {
                    OletxTransactionManager.ProxyException(comException);
                    throw;
                }
                finally
                {
                    oletxTm.DtcTransactionManagerLock.ReleaseReaderLock();
                }

                // We need to create a new RealOletxTransaction.
                realTx = new RealOletxTransaction(
                    oletxTm,
                    transactionShim,
                    outcomeEnlistment,
                    txIdentifier,
                    oletxIsoLevel);

                oleTx = new OletxTransaction(realTx);

                // If a transaction is found then FindOrCreate will Dispose the oletx
                // created.
                transaction = TransactionManager.FindOrCreatePromotedTransaction(xactInfo.Uow, oleTx);
            }
            else
            {
                // It was too late to do a clone of the provided ITransactionNative, so we are just going to
                // create a RealOletxTransaction without a transaction shim or outcome enlistment.
                realTx = new RealOletxTransaction(
                    oletxTm,
                    null,
                    null,
                    txIdentifier,
                    OletxTransactionIsolationLevel.ISOLATIONLEVEL_SERIALIZABLE);

                oleTx = new OletxTransaction(realTx);
                transaction = new Transaction(oleTx);
                TransactionManager.FireDistributedTransactionStarted(transaction);
                oleTx.SavedLtmPromotedTransaction = transaction;

                InternalTransaction.DistributedTransactionOutcome(transaction._internalTransaction, TransactionStatus.InDoubt);
            }

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.{nameof(GetTransactionFromDtcTransaction)}");
            }

            return transaction;
        }

        internal static ITransaction GetITransactionFromIDtcTransaction(IDtcTransaction transactionNative)
        {
            if (Marshal.GetComObjectData(transactionNative, typeof(ITransaction)) is not ITransaction myTransactionNative)
            {
                unsafe
                {
                    nint unknown = Marshal.GetIUnknownForObject(transactionNative);
                    if (Marshal.QueryInterface(unknown, Guids.IID_ITransaction_Guid, out IntPtr transactionNativePtr) == 0)
                    {
                        Marshal.Release(unknown);
                        myTransactionNative = ComInterfaceMarshaller<ITransaction>.ConvertToManaged((void*)transactionNativePtr)!;
                        Marshal.SetComObjectData(transactionNative, typeof(ITransaction), myTransactionNative);
                        Marshal.Release(transactionNativePtr);
                    }
                    else
                    {
                        Marshal.Release(unknown);
                        throw new ArgumentException(SR.InvalidArgument, nameof(transactionNative));
                    }
                }
            }

            return myTransactionNative;
        }

        public static byte[] GetWhereabouts()
        {
            TransactionsEtwProvider etwLog = TransactionsEtwProvider.Log;
            if (etwLog.IsEnabled())
            {
                etwLog.MethodEnter(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.${nameof(GetWhereabouts)}");
            }

            OletxTransactionManager oletxTm = TransactionManager.DistributedTransactionManager;
            if (oletxTm == null)
            {
                throw new ArgumentException(SR.InvalidArgument, "transactionManager");
            }

            byte[]? returnValue;

            oletxTm.DtcTransactionManagerLock.AcquireReaderLock(-1);
            try
            {
                returnValue = oletxTm.DtcTransactionManager.Whereabouts;
            }
            finally
            {
                oletxTm.DtcTransactionManagerLock.ReleaseReaderLock();
            }

            if (etwLog.IsEnabled())
            {
                etwLog.MethodExit(TraceSourceType.TraceSourceOleTx, $"{nameof(TransactionInterop)}.${nameof(GetWhereabouts)}");
            }

            return returnValue;
        }

        internal static OletxTransaction GetOletxTransactionFromTransmitterPropagationToken(byte[] propagationToken)
        {
            ArgumentNullException.ThrowIfNull(propagationToken);

            if (propagationToken.Length < 24)
            {
                throw new ArgumentException(SR.InvalidArgument, nameof(propagationToken));
            }

            Guid identifier;
            OletxTransactionIsolationLevel oletxIsoLevel;
            OutcomeEnlistment outcomeEnlistment;
            TransactionShim? transactionShim = null;

            byte[] propagationTokenCopy = new byte[propagationToken.Length];
            Array.Copy(propagationToken, propagationTokenCopy, propagationToken.Length);
            propagationToken = propagationTokenCopy;

            // First we need to create an OletxTransactionManager from Config.
            OletxTransactionManager oletxTm = TransactionManager.DistributedTransactionManager;

            oletxTm.DtcTransactionManagerLock.AcquireReaderLock(-1);
            try
            {
                outcomeEnlistment = new OutcomeEnlistment();
                oletxTm.DtcTransactionManager.ProxyShimFactory.ReceiveTransaction(
                    propagationToken,
                    outcomeEnlistment,
                    out identifier,
                    out oletxIsoLevel,
                    out transactionShim);
            }
            catch (COMException comException)
            {
                OletxTransactionManager.ProxyException(comException);

                // We are unsure of what the exception may mean.  It is possible that
                // we could get E_FAIL when trying to contact a transaction manager that is
                // being blocked by a fire wall.  On the other hand we may get a COMException
                // based on bad data.  The more common situation is that the data is fine
                // (since it is generated by Microsoft code) and the problem is with
                // communication.  So in this case we default for unknown exceptions to
                // assume that the problem is with communication.
                throw TransactionManagerCommunicationException.Create(SR.TraceSourceOletx, comException);
            }
            finally
            {
                oletxTm.DtcTransactionManagerLock.ReleaseReaderLock();
            }

            var realTx = new RealOletxTransaction(
                oletxTm,
                transactionShim,
                outcomeEnlistment,
                identifier,
                oletxIsoLevel);

            return new OletxTransaction(realTx);
        }
    }
}
