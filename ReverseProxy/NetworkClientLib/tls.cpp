#include "tls.h"
#include "utils.h"

namespace NetworkOperations
{
#if defined(ENABLE_SCHANNEL)

	SchannelTLS::SchannelTLS()
	{
		_transport = NULL;
		_cert_ctx = NULL;
	}

	SchannelTLS::~SchannelTLS()
	{
		SECURITY_STATUS sec_status = SEC_E_OK;
		if (SecIsValidHandle(&_context))
		{
			sec_status = DeleteSecurityContext(&_context);
			if (sec_status != SEC_E_OK)
			{
				LOG_ERROR_A("[SchannelTLS] DeleteSecurityContext() returned error = %ld", sec_status);
			}
		}
		if (SecIsValidHandle(&_handle))
		{
			sec_status = FreeCredentialsHandle(&_handle);
			if (sec_status != SEC_E_OK)
			{
				LOG_ERROR_A("[SchannelTLS] FreeCredentialsHandle() returned error = %ld", sec_status);
			}
		}
		if (_cert_ctx)
		{
			if (!CertDeleteCertificateFromStore(_cert_ctx))
			{
				LOG_ERROR_A("[SchannelTLS] CertDeleteCertificateFromStore() returned error = %ld", GetLastError());
			}
			else
			{
				CertFreeCertificateContext(_cert_ctx);
			}
		}
	}

	bool SchannelTLS::set_trusted_ca(const char* cert_path, const char* password, const char* subject_name)
	{
		BYTE* buffer = NULL;
		DWORD buffer_size = 0;
		std::wstring cert_path_w = Helper::StringHelper::convertStringToWideString(cert_path);
		if (!Helper::FileHelper::ReadFileData(cert_path_w, buffer, buffer_size))
		{
			LOG_ERROR_W(L"[SchannelTLS] Failed to read certificate from the %s", cert_path_w.c_str());
			return false;
		}
		// Prepare the CRYPT_DATA_BLOB structure
		CRYPT_DATA_BLOB blob;
		blob.pbData = buffer;
		blob.cbData = buffer_size;

		// Import the certificate store from the PFX file
		HCERTSTORE hTrustStore = PFXImportCertStore(&blob, password ? Helper::StringHelper::convertStringToWideString(password).c_str() : NULL, 0);
		if (!hTrustStore)
		{
			LOG_ERROR_W(L"[SchannelTLS] Failed to import certificate to store!");
			return false;
		}
		// Find the first certificate in the store
		this->_cert_ctx = CertFindCertificateInStore(hTrustStore,
													 X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
													 0,
													 CERT_FIND_SUBJECT_STR_W,
													 (LPVOID)Helper::StringHelper::convertStringToWideString(subject_name).c_str(),
													 NULL);
		if (_cert_ctx == NULL)
		{
			LOG_ERROR_W(L"Failed to find a certificate with subject name %s in the store.", subject_name);
			CertCloseStore(hTrustStore, 0);
			delete[] buffer;
			return false;
		}
		// Clean up
		if (buffer)
		{
			delete[] buffer;
		}
		return true;
	}

	bool SchannelTLS::initialize(void* ctx)
	{
		if (!ctx) 
		{
			LOG_ERROR_A("[SchannelTLS] ITransport context is null!");
			return false;
		}
		_transport = reinterpret_cast<ITransport*>(ctx);
	
		// Initialize a credentials handle for Secure Channel.
		SCHANNEL_CRED cred_data = { 0 };
		cred_data.dwVersion = SCHANNEL_CRED_VERSION;
		cred_data.dwFlags = SCH_USE_STRONG_CRYPTO	// Disable deprecated or otherwise weak algorithms (on as default).
			| SCH_CRED_NO_DEFAULT_CREDS				// Client certs are not supported.
			| SCH_CRED_MANUAL_CRED_VALIDATION;		// Disable Schannel's automatic server cert validation; the app must validate manually.
													// Enable automatically validate server cert (on as default) = SCH_CRED_AUTO_CRED_VALIDATION.	
		if (_cert_ctx)
		{
			cred_data.cCreds = 1;
			cred_data.paCred = &_cert_ctx;
		}
		OSVERSIONINFOEXW osvi;
		SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		typedef LONG(__stdcall* RtlGetVersion)(LPOSVERSIONINFOEXW);
		if (const HMODULE ntdll = GetModuleHandleW(L"ntdll"))
		{
			if (const RtlGetVersion pRtlGetVersion = (RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion"))
			{
				if (pRtlGetVersion(&osvi) == 0)
				{
					if (osvi.dwMajorVersion <= 6) {
						if (osvi.dwMinorVersion < 2) {
							// WIN 7
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
						}
						else {
							// WIN 8, WIN 8.1
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
						}
					}
					else {
						// WIN 10, WIN 11
						cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
					}
				}
			}
		}
		SECURITY_STATUS sec_status = AcquireCredentialsHandleA(
			NULL,				   // default principal
			(LPSTR)UNISP_NAME_A,   // name of the SSP
			SECPKG_CRED_OUTBOUND,  // client will use the credentials
			NULL,                  // use the current LOGON id
			&cred_data,            // protocol-specific data
			NULL,                  // default
			NULL,                  // default
			&_handle,			   // receives the credential handle
			NULL);				   // receives the credential time limit
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] AcquireCredentialsHandleW() returned error = %ld", sec_status);
			return false;
		}
		return true;
	}

	bool SchannelTLS::perform_handshake(const char* host_name, bool verify_server_cert)
	{			
		// TLS handshake algorithm.
		// 1. Call InitializeSecurityContext.
		//    The first call creates a security context.
		//    Subsequent calls update the security context.
		// 2. Check InitializeSecurityContext's return value.
		//    SEC_E_OK                     - Handshake completed, TLS tunnel ready to go.
		//    SEC_I_CONTINUE_NEEDED        - Success, keep calling InitializeSecurityContext (send).
		//    SEC_E_INCOMPLETE_MESSAGE     - Success, continue reading data from the server (recv).
		//    SEC_I_INCOMPLETE_CREDENTIALS - The server asked for client certs.
		// 3. Otherwise an error may have been encountered. Set an error state and return.
		// 4. Read data from the server (recv).

		SECURITY_STATUS sec_status = SEC_E_OK;
		if (!establish_client_security_context_first_stage(host_name))
		{
			return false;
		}
		if (!establish_client_security_context_second_stage(host_name, verify_server_cert))
		{
			return false;
		}
		return true;
	}

	int SchannelTLS::read_data(char* data, int len)
	{
		if (!data || len == 0)
		{
			return -1;
		}
		SecPkgContext_StreamSizes stream_sizes = get_stream_sizes(_context);
		int total_bytes_readed = 0;
		while (len > 0)
		{
			int len_use = min((unsigned long)len, stream_sizes.cbMaximumMessage);
			{
				auto encrypted_buf = std::make_unique<char[]>(TLS_MAX_PACKET_SIZE);
				int bytes_received = _transport->tcp_recv_data(encrypted_buf.get(), TLS_MAX_PACKET_SIZE);
				if (bytes_received <= 0)
				{
					LOG_ERROR_A("[SchannelTLS] tcp_recv_data() failed! Error code: %d", bytes_received);
					return -1;
				}
				int decrypted_len = decrypt_data(_context,
					stream_sizes,
					encrypted_buf.get(), bytes_received,
					data, len_use);
				if (decrypted_len == -1)
				{
					LOG_ERROR_A("[SchannelTLS] decrypt_data() failed!");
					return -1;
				}
				if (decrypted_len == SEC_E_INCOMPLETE_MESSAGE)
				{

				}
				total_bytes_readed += bytes_received;
			}
			data = (PCHAR)(data)+len_use;
			len -= len_use;
		}
		return total_bytes_readed;
	}

	int SchannelTLS::write_data(const char* data, int len)
	{
		if (!data || len == 0) 
		{
			return -1;
		}
		SecPkgContext_StreamSizes stream_sizes = get_stream_sizes(_context);
		int total_bytes_writed = 0;
		while (len > 0) 
		{
			int len_use = min((unsigned long)len, stream_sizes.cbMaximumMessage);
			{
				auto encrypted_buf = std::make_unique<char[]>(TLS_MAX_PACKET_SIZE);
				int encrypted_len = encrypt_data(_context,
												 stream_sizes,
												 data, len_use,
												 encrypted_buf.get(),
												 TLS_MAX_PACKET_SIZE);
				if (encrypted_len == -1)
				{
					LOG_ERROR_A("[SchannelTLS] encrypt_data() failed!");
					return -1;
				}
				int bytes_sented = _transport->tcp_send_data(encrypted_buf.get(), encrypted_len);
				if (bytes_sented <= 0)
				{
					LOG_ERROR_A("[SchannelTLS] tcp_send_data() failed! Error code: %d", bytes_sented);
					return -1;
				}
				total_bytes_writed += bytes_sented;
			}
			data = (PCHAR)(data) + len_use;
			len -= len_use;	
		}
		return total_bytes_writed;
	}

	bool SchannelTLS::shutdown()
	{
		SECURITY_STATUS sec_status;
		DWORD dwShutdown = SCHANNEL_SHUTDOWN;
		SecBuffer close_buffer_in[1];
		init_sec_buffer(close_buffer_in[0], SECBUFFER_TOKEN, sizeof(dwShutdown), &dwShutdown);

		SecBufferDesc close_buffer_in_desc;
		init_sec_buffer_desc(close_buffer_in_desc, SECBUFFER_VERSION, 1, close_buffer_in);

		sec_status = ApplyControlToken(&_context, &close_buffer_in_desc);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] ApplyControlToken: %ld", sec_status);
			return false;
		}
		SecBuffer close_buffer_out[2];
		init_sec_buffer(close_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
		init_sec_buffer(close_buffer_out[1], SECBUFFER_EMPTY, 0, nullptr);

		SecBufferDesc close_buffer_out_desc;
		init_sec_buffer_desc(close_buffer_out_desc, SECBUFFER_VERSION, 2, close_buffer_out);
		Helper::DeferFunctionRAII free_buffers_deferred([&close_buffer_out_desc]() { free_all_buffers(close_buffer_out_desc); });
		
		/* Security request flags */
		DWORD dwFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
						ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
						ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
		sec_status = InitializeSecurityContextA(
			&_handle, 
			&_context,
			NULL,
			dwFlags,
			0,
			SECURITY_NATIVE_DREP,
			NULL,
			0,
			NULL,
			&close_buffer_out_desc,
			&dwFlags,
			NULL);
		if (sec_status != SEC_E_OK && sec_status != SEC_I_CONTEXT_EXPIRED)
		{
			LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
			return false;
		}
		if (close_buffer_out[0].pvBuffer && close_buffer_out[0].cbBuffer > 0)
		{		
			// Send TLS close_notify
			int bytes_sented = _transport->tcp_send_data((char*)close_buffer_out[0].pvBuffer, close_buffer_out[0].cbBuffer);
			if (bytes_sented <= 0)
			{
				LOG_ERROR_A("[SchannelTLS] tcp_send_data() failed! Error code: %d", bytes_sented);
				return false;
			}
		}
		return true;
	}

	bool SchannelTLS::establish_client_security_context_first_stage(const char* host_name)
	{
		SecBuffer secure_buffer_out[1] = { 0 };
		init_sec_buffer(secure_buffer_out[0], SECBUFFER_EMPTY, 0, NULL);

		SecBufferDesc secure_buffer_desc_out = { 0 };
		init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 1, secure_buffer_out);
		Helper::DeferFunctionRAII free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });
		
		/* Security request flags */
		DWORD dwFlags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | 
						ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
						ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
		SECURITY_STATUS sec_status = InitializeSecurityContextA(
										&_handle, 
										NULL, // Must be null on first call
										(SEC_CHAR*)host_name,
										dwFlags,
										0,
										0,
										NULL, // Must be null on first call
										0,
										&_context,	
										&secure_buffer_desc_out,
										&dwFlags,
										NULL);
		if (sec_status != SEC_I_CONTINUE_NEEDED)
		{
			LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
			return false;
		}
		if (secure_buffer_out[0].pvBuffer && secure_buffer_out[0].cbBuffer > 0)
		{
			int bytes_sented = _transport->tcp_send_data((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
			if (bytes_sented <= 0)
			{
				LOG_ERROR_A("[SchannelTLS] tcp_send_data() failed! Error code: %d", bytes_sented);
				return false;
			}
		}
		return true;
	}

	bool SchannelTLS::establish_client_security_context_second_stage(const char* host_name, bool verify_server_cert)
	{
		int offset = 0;
		bool skip = false;
		auto in_buffer = std::make_unique<char[]>(TLS_MAX_RECORD_SIZE);
		do
		{
			int in_buffer_size = 0;
			if (!skip)
			{
				int bytes_received = _transport->tcp_recv_data(in_buffer.get() + offset, TLS_MAX_RECORD_SIZE);
				if (bytes_received == 0)
				{
					LOG_ERROR_A("[SchannelTLS] Server disconnected socket!");
					return false;
				}
				if (bytes_received < 0) 
				{
					LOG_ERROR_A("[SchannelTLS] tcp_recv_data() failed! Error code: %d", bytes_received);
					return false;
				}
				in_buffer_size = bytes_received + offset;
			}
			else 
			{
				in_buffer_size = offset;
			}
			skip = false;	
			offset = 0;

			// Input buffer
			SecBuffer secure_buffer_in[4] = { 0 };
			init_sec_buffer(secure_buffer_in[0], SECBUFFER_TOKEN, in_buffer_size, in_buffer.get());
			init_sec_buffer(secure_buffer_in[1], SECBUFFER_EMPTY, 0, nullptr);
			init_sec_buffer(secure_buffer_in[2], SECBUFFER_EMPTY, 0, nullptr);
			init_sec_buffer(secure_buffer_in[3], SECBUFFER_EMPTY, 0, nullptr);

			SecBufferDesc secure_buffer_desc_in = { 0 };
			init_sec_buffer_desc(secure_buffer_desc_in, SECBUFFER_VERSION, 4, secure_buffer_in);

			// Output buffer
			SecBuffer secure_buffer_out[3] = { 0 };
			init_sec_buffer(secure_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
			init_sec_buffer(secure_buffer_out[1], SECBUFFER_ALERT, 0, nullptr);
			init_sec_buffer(secure_buffer_out[2], SECBUFFER_EMPTY, 0, nullptr);

			SecBufferDesc secure_buffer_desc_out = { 0 };
			init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 3, secure_buffer_out);
			Helper::DeferFunctionRAII free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

			 /* Security request flags */
			DWORD dwFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
							ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
							ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
			if (verify_server_cert) 
			{
				// Used for manual validation in SSPI-based security contexts.
				dwFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;
			}
			else
			{
				dwFlags |= ISC_REQ_USE_SUPPLIED_CREDS;
			}

			/* https://learn.microsoft.com/en-us/windows/win32/secauthn/manually-validating-schannel-credentials?redirectedfrom=MSDN */
			SECURITY_STATUS sec_status = InitializeSecurityContextA(
											&_handle, 
											&_context,
											NULL,
											dwFlags,
											0,
											0,
											&secure_buffer_desc_in,
											0,
											NULL,
											&secure_buffer_desc_out,
											&dwFlags,
											NULL);
			switch (sec_status) 
			{
			case SEC_E_OK:
				// Successfully completed handshake. TLS tunnel is now operational.
				return true;
			case SEC_I_CONTINUE_NEEDED:
			{
				// Continue sending data to the server.
				const char* buffer = (const char*)secure_buffer_out[0].pvBuffer;
				unsigned long size = secure_buffer_out[0].cbBuffer;
				if (!buffer || size == 0) 
				{
					return false;
				}
				while (size > 0) 
				{
					int bytes_sented = _transport->tcp_send_data(buffer, size);
					if (bytes_sented <= 0)
					{
						break;
					}
					buffer += bytes_sented;
					size -= bytes_sented;
				}
				// Fetch incoming data.
				if (secure_buffer_in[1].BufferType == SECBUFFER_EXTRA)
				{
					offset = secure_buffer_in[0].cbBuffer - secure_buffer_in[1].cbBuffer;
					MoveMemory(in_buffer.get(), in_buffer.get() + offset, secure_buffer_in[1].cbBuffer);
					offset = secure_buffer_in[1].cbBuffer;
					skip = true;
				}		
				if (secure_buffer_in[1].BufferType == SECBUFFER_MISSING) 
				{
					offset = 0;
				}
				break;
			}
			case SEC_E_INCOMPLETE_MESSAGE:
				// Need to read more bytes.
				offset = secure_buffer_in[0].cbBuffer;
				break;
			case SEC_I_INCOMPLETE_CREDENTIALS:
				LOG_ERROR_A("[SchannelTLS] Server requests client certificate (not supported here): %ld", sec_status);
				return false;
			default:
				LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
				return false;
			}
		} while (true);

		return true;
	}

	SecPkgContext_StreamSizes SchannelTLS::get_stream_sizes(CtxtHandle security_context)
	{
		SecPkgContext_StreamSizes stream_sizes = { 0 };
		SECURITY_STATUS sec_status = QueryContextAttributesA(&security_context, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] ssl_get_stream_sizes() failed! QueryContextAttributes() returned error = %ld", sec_status);
			return { 0 };
		}
		return stream_sizes;
	}

	int SchannelTLS::encrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len)
	{
		int min_out_len = in_len + stream_sizes.cbHeader + stream_sizes.cbTrailer;
		if (min_out_len > (int)stream_sizes.cbMaximumMessage)
		{
			LOG_ERROR_A("[SchannelTLS] Message is too long!");
			return SEC_E_INVALID_PARAMETER;
		}
		if (min_out_len > TLS_MAX_RECORD_SIZE)
		{
			LOG_ERROR_A("[SchannelTLS] Output buffer is too small!");
			return SEC_E_INSUFFICIENT_MEMORY;
		}
		auto encrypt_buf = std::make_unique<char[]>(out_len);

		SecBuffer secure_buffers[4] = { 0 };
		init_sec_buffer(secure_buffers[0], SECBUFFER_STREAM_HEADER, stream_sizes.cbHeader, encrypt_buf.get());
		init_sec_buffer(secure_buffers[1], SECBUFFER_DATA, in_len, encrypt_buf.get() + stream_sizes.cbHeader);
		init_sec_buffer(secure_buffers[2], SECBUFFER_STREAM_TRAILER, stream_sizes.cbTrailer, encrypt_buf.get() + stream_sizes.cbHeader + in_len);
		init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
		// Copy in_buf -> SECBUFFER_DATA
		if (secure_buffers[1].pvBuffer)
		{
			CopyMemory(secure_buffers[1].pvBuffer, in_buf, in_len);
		}
		SecBufferDesc secure_buffer_desc = { 0 };
		init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

		SECURITY_STATUS sec_status = EncryptMessage(&security_context, 0, &secure_buffer_desc, 0);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] EncryptMessage() returned error %ld", sec_status);
			return sec_status;
		}
		// HEADER + DATA + TRAILER
		int encrypt_buf_size = secure_buffers[0].cbBuffer + secure_buffers[1].cbBuffer + secure_buffers[2].cbBuffer;
		CopyMemory(out_buf, encrypt_buf.get(), min(encrypt_buf_size, out_len));
		return encrypt_buf_size;
	}

	int SchannelTLS::decrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len)
	{
		int min_out_len = in_len - stream_sizes.cbHeader - stream_sizes.cbTrailer;
		if (min_out_len > (int)stream_sizes.cbMaximumMessage)
		{
			LOG_ERROR_A("[SchannelTLS] Message to is too long!");
			return SEC_E_INVALID_PARAMETER;
		}
		if (min_out_len > TLS_MAX_RECORD_SIZE)
		{
			LOG_ERROR_A("[SchannelTLS] Output buffer is too small!");
			return SEC_E_INSUFFICIENT_MEMORY;
		}
		auto decrypt_buf = std::make_unique<char[]>(in_len);

		SecBuffer secure_buffers[4] = { 0 };
		init_sec_buffer(secure_buffers[0], SECBUFFER_DATA, in_len, decrypt_buf.get());
		init_sec_buffer(secure_buffers[1], SECBUFFER_EMPTY, 0, nullptr);
		init_sec_buffer(secure_buffers[2], SECBUFFER_EMPTY, 0, nullptr);
		init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
		// Copy in_buf -> SECBUFFER_DATA
		if (secure_buffers[0].pvBuffer)
		{
			CopyMemory(secure_buffers[0].pvBuffer, in_buf, in_len);
		}
		SecBufferDesc secure_buffer_desc = { 0 };
		init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

		SECURITY_STATUS sec_status = DecryptMessage(&security_context, &secure_buffer_desc, 0, NULL);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] DecryptMessage() returned error %ld", sec_status);
			return sec_status;
		}
		// DATA
		int decrypt_buf_size = secure_buffers[1].cbBuffer;
		CopyMemory(out_buf, secure_buffers[1].pvBuffer, min(decrypt_buf_size, out_len));
		return decrypt_buf_size;
	}

	void SchannelTLS::init_sec_buffer_desc(SecBufferDesc& secure_buffer_desc, unsigned long version, unsigned long num_buffers, SecBuffer* buffers)
	{
		secure_buffer_desc.ulVersion = version;
		secure_buffer_desc.cBuffers = num_buffers;
		secure_buffer_desc.pBuffers = buffers;
	}

	void SchannelTLS::init_sec_buffer(SecBuffer& secure_buffer, unsigned long type, unsigned long len, void* buffer)
	{
		secure_buffer.BufferType = type;
		secure_buffer.cbBuffer = len;
		secure_buffer.pvBuffer = buffer;
	}

	void SchannelTLS::free_all_buffers(SecBufferDesc& secure_buffer_desc)
	{
		for (unsigned long i = 0; i < secure_buffer_desc.cBuffers; ++i)
		{
			auto buffer = secure_buffer_desc.pBuffers[i].pvBuffer;
			if (buffer != nullptr)
			{
				FreeContextBuffer(buffer);
			}
		}
	}

#elif defined(ENABLE_MBEDTLS)

	MbedTLS::MbedTLS()
	{
		mbedtls_ssl_init(&_ssl);
		mbedtls_ssl_config_init(&_conf);
		mbedtls_ctr_drbg_init(&_ctr_drbg);
		mbedtls_entropy_init(&_entropy);
		mbedtls_x509_crt_init(&_cacert);
		mbedtls_pk_init(&_pkey);
	}

	MbedTLS::~MbedTLS()
	{
		mbedtls_ssl_free(&_ssl);
		mbedtls_ssl_config_free(&_conf);
		mbedtls_ctr_drbg_free(&_ctr_drbg);
		mbedtls_entropy_free(&_entropy);
		mbedtls_x509_crt_free(&_cacert);
		mbedtls_pk_free(&_pkey);
	}

	bool MbedTLS::set_trusted_ca(const char* cert_path, const char* password, const char* subject_name)
	{
		int error = mbedtls_x509_crt_parse_file(&_cacert, cert_path);
		if (error != 0)
		{
			char error_buf[128];
			mbedtls_strerror(error, error_buf, sizeof(error_buf));
			LOG_ERROR_A("[MbedTLS] Failed to parse cert: %s (%d)\n", error_buf, error);
			return false;
		}
		mbedtls_ssl_conf_ca_chain(&_conf, &_cacert, nullptr);
		return true;
	}

	bool MbedTLS::initialize(void* ctx)
	{
		int ret = 0;
		/*
			Configure SSL defaults
		*/
		ret = mbedtls_ssl_config_defaults(&_conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		if (ret != 0)
		{
			LOG_ERROR_A("[MbedTLS] mbedtls_ssl_config_defaults failed: -0x%04X", -ret);
			return false;
		}
		/*
			Set the certificate verification mode.
				Default: NONE on server, REQUIRED on client

			- MBEDTLS_SSL_VERIFY_NONE: peer certificate is not checked
								  (default on server)
								  (insecure on client)
			- MBEDTLS_SSL_VERIFY_OPTIONAL: peer certificate is checked, however the
								  handshake continues even if verification failed;
								  mbedtls_ssl_get_verify_result() can be called after the
								  handshake is complete.
			- MBEDTLS_SSL_VERIFY_REQUIRED: peer *must* present a valid certificate,
								  handshake is aborted if verification failed.
								  (default on client)
		*/
		mbedtls_ssl_conf_authmode(&_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		/*
			Debug levels:
			- 0 No debug
			- 1 Error
			- 2 State change
			- 3 Informational
			- 4 Verbose
		*/
		mbedtls_ssl_conf_dbg(&_conf, debug_printf, stdout);
		mbedtls_debug_set_threshold(MBEDTLS_DEBUG_LEVEL);
		/*
			Seed the RNG (Counter mode Deterministic Random Bit Generator)
		*/
		ret = mbedtls_ctr_drbg_seed(&_ctr_drbg, mbedtls_entropy_func, &_entropy, NULL, 0);
		if (ret != 0)
		{
			LOG_ERROR_A("[MbedTLS] mbedtls_ctr_drbg_seed failed: -0x%04X", -ret);
			return false;
		}
		/*
			Set RNG (Random number generator callback)
		*/
		mbedtls_ssl_conf_rng(&_conf, mbedtls_ctr_drbg_random, &_ctr_drbg);
		/*
			Setup SSL context
		*/
		ret = mbedtls_ssl_setup(&_ssl, &_conf);
		if (ret != 0)
		{
			LOG_ERROR_A("[MbedTLS] mbedtls_ssl_setup failed: -0x%04X", -ret);
			return false;
		}
		/*
			Set BIO callbacks
			- ssl      SSL context
			- p_bio    parameter (context) shared by BIO callbacks
			- f_send   write callback
			- f_recv   read callback
		*/
		mbedtls_ssl_set_bio(&_ssl, ctx, transport_send, transport_recv, nullptr);

		return true;
	}

	bool MbedTLS::perform_handshake(const char* host_name, bool verify_server_cert)
	{
		int status = 0;
		if ((status = mbedtls_ssl_set_hostname(&_ssl, host_name)) != 0)
		{
			LOG_ERROR_A("[MbedTLS] mbedtls_ssl_set_hostname (-0x%X)", -status);
			return false;
		}
		while ((status = mbedtls_ssl_handshake(&_ssl)) != 0)
		{
			if (status != MBEDTLS_ERR_SSL_WANT_READ && status != MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				LOG_ERROR_A("[MbedTLS] mbedtls_ssl_handshake (-0x%X)", -status);
				return false;
			}
		}
		if (verify_server_cert)
		{
			if ((status = mbedtls_ssl_get_verify_result(&_ssl)) != 0)
			{
				char verify_buf[512];
				mbedtls_x509_crt_verify_info(verify_buf, sizeof(verify_buf), "  ! ", status);
				LOG_ERROR_A("[MbedTLS]  mbedtls_x509_crt_verify_info %s", verify_buf);
				return false;
			}
			LOG_INFO_A("[MbedTLS] Verifying peer X.509 certificate... ok");
		}
		return true;
	}

	int MbedTLS::read_data(char* data, int len)
	{
		int bytes_read = 0;
		while (true)
		{
			int ret = mbedtls_ssl_read(&_ssl, (unsigned char*)(data + bytes_read), len - bytes_read);
			if (ret > 0)
			{
				bytes_read += ret;
				break;
			}
			if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				continue;
			}
			if (ret == 0)
			{
				LOG_ERROR_A("[MbedTLS] Connection closed by peer!");
				return 0;
			}
			LOG_ERROR_A("[MbedTLS] mbedtls_ssl_read returned error: %d", ret);
			return -1;
		}
		return bytes_read;
	}

	int MbedTLS::write_data(const char* data, int len)
	{
		int bytes_written = 0;
		while (bytes_written < len)
		{
			int ret = mbedtls_ssl_write(&_ssl, (const unsigned char*)(data + bytes_written), len - bytes_written);
			if (ret > 0)
			{
				bytes_written += ret;
				continue;
			}
			if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
			{
				continue;
			}
			LOG_ERROR_A("[MbedTLS] mbedtls_ssl_write returned error: %d", ret);
			return -1;
		}
		return bytes_written;
	}

	bool MbedTLS::shutdown()
	{
		if (mbedtls_ssl_close_notify(&_ssl) != 0)
		{
			return false;
		}
		return true;
	}

	void MbedTLS::debug_printf(void* ctx, int level, const char* file, int line, const char* str)
	{
		((void)level);
		fprintf((FILE*)ctx, "%s:%04d: %s", file, line, str);
	}

	int MbedTLS::transport_recv(void* ctx, unsigned char* buf, size_t len)
	{
		ITransport* transport = reinterpret_cast<ITransport*>(ctx);
		return transport->tcp_recv_data((char*)buf, (int)len);
	}

	int MbedTLS::transport_send(void* ctx, const unsigned char* buf, size_t len)
	{
		ITransport* transport = reinterpret_cast<ITransport*>(ctx);
		return transport->tcp_send_data((const char*)buf, (int)len);
	}

#elif defined(ENABLE_WOLFSSL)

#else

#endif
}	/* NetworkOperations */