import { UserManagement } from '../user/user';
import { TestKeys } from './utils';
import { createFetchSender } from '../utils/fetchSender';
import { AccessLog } from '../logs/accessLog';

const goDecryptB =
  '{"protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJaSVlKUGJIV0FCajR6TE5fN2ZjQmNLZDdBc2FYR0hWV21tRVdZR1JkdFpJIiwieSI6IkNWVkdaTTcwY2hzSE5XNERVdzYzOGlfbjlfbDJsOU5ySE1wdV8zcUxfSHMifSwib3duZXIiOiJyZWNlaXZlciIsInJlY2lwaWVudHMiOlsicmVjZWl2ZXIiXX0","encrypted_key":"YpXML6TelUH2_IfZ4Mp8V6X-TtQJ_wRDvcsqS86Ek_vXVm55ccKChw","iv":"NNRBGdYDDBDaYtqI","ciphertext":"OTorTIsCmSRckWp-Fu206TzVhznFlANOer7xtp2nnwdcgEI1zMJt7prfkkCUtWxON7eDzKZneBdNPvnWz_rIrXFv7LVTU6o871JS7ur8nguml37Wa_d0az-l_K-Pub9wf7mv7Zi00q40kYoQIINb9eeh8Vx5NqKTSlMqcNgaWo4wpne2j-puZbgRdSPEx5bXWr0DO0VWIlUFWabyfdn_ry6A-AY8XFWg5-A91Mv93womAY5JLIJ5kLp9YsikjxaIjlyQrWZHcMqApxXRALrKw4_tdHvMHCD0VLJ6S3PCQwNGrDRTlV7d9NORM9qXshJ8cqA1b6_n1ArzXl2qssmjtWAHeQCuamfKTBchbTTEvJMv7K7jlbFl_HvUYh7FFL5DQrkKP2QwLXPXT6k8rJ4EsvCXYkve4wi-3szQccfVaNGoa60aD5HWuZnA_cg5DxO99d0Bd4J3KFzcRNezxB3rWIU-jFgw6JxyPeuw377dsz79n0ELbR8oDjo_X1kJdYOyXw0o6vT9iWnGAcbkwL3AJnqoomVvQBYfmGf700jJiQlpFhChEk18OkIRB8V8NLB0RmFqDyWZnwOxYgLGWFw7DZV2DvPPznuON3xKlCfSWYbkVOvBMnI6UNgi5HoZm_7FJzxVluuoPIzsYPoFCzZlwSD9wjdxUuSiB3POQ3ddjLZG_QNDdg6TymRYPd1g8Frx_SkWvcoOF4_gS6DSFfdGlQdGGGHjRgn_PhwgLxoQfV4bPpcI1A3pdumIyeN51uVBSaVgRoeLoxSDEETjXmeYVikJlyUCwC_eHH4RYLx4jd3Y-JJpg29MnIFYldM_YISm-h1pd7ll7AFhOfoO4Q6oBh3llQsfnnJEE4Pfd1hi-54oODLZyokaDlBhaTmtTXcehSlYbNKJskxx5vRTJTkPp_nFgylGoAXJcQ","tag":"OgDgamFQ_CboQQzVkM180g"}';

const goDecryptAB =
  '{"protected":"eyJlbmMiOiJBMjU2R0NNIiwib3duZXIiOiJyZWNlaXZlciIsInJlY2lwaWVudHMiOlsicmVjZWl2ZXIiLCJzZW5kZXIiXX0","recipients":[{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"UtvrweEFgc7pM-Nw9XKiH2ovyRq5W1pBgHj7ol71MBc","y":"qsOgb81zywM4vmxgF99WYWDy7YpqH92IDzqR-dROi5w"}},"encrypted_key":"-Q_Pg_V-Vn_77xFEhGtYaJUolRtOPHn4OFC44rBQYx4ag7KyZOQEmg"},{"header":{"alg":"ECDH-ES+A256KW","epk":{"kty":"EC","crv":"P-256","x":"yNLs1ta3xpu8i1qaK7TJKAVlXSlCijjCkgRKRyCJBds","y":"iJEWORvfKCKMHV72GcyfMrlumrJGl21xVHqYzQEijAU"}},"encrypted_key":"jsBZPnZaZb1-uxRhjD6sEhJshq0zQwsg1Zj7azGxOLM5QeXrGj6LMA"}],"encrypted_key":"-Q_Pg_V-Vn_77xFEhGtYaJUolRtOPHn4OFC44rBQYx4ag7KyZOQEmg","iv":"GNVnQbynVTKfnen0","ciphertext":"7AJAgmFi2Tk2UUyvT4ZGOjYVDsK_gft2yEhfV5mZITesUPNUQPQ2U-XY7jPYSxDi6xmLESv22JXpJNlTBU4VREbKYD9EvNhyCNzjIVTp2VNCNPih5FOdhg8oRymeCjNInyXGSPXWJBTGoXcIr6Qr_i0CArMV6khgOYtsaoQelzgirtk2upsYjghWKluwSgvmcl9BYd0pqovkiobADLc66AwIb-CA6Up-kBrCdhdL0faw-SAyBIyau0LHGU2eMlpPNmBGIu29ZaLLDN7dhI9hGndHQwYUwq5d65-eGNo_82DFzgVeTxwUKSKSm9S_bgZ0YapDVBt2S9Y9KnGT1PsxK7_gKWcfL-uvN_t8odRvUrexUIExb68xs-zvn0b69wnR--40zVdB0KYODFl8qIj-G2a3Np4gmK6ENTi2LYBrMhUfAVDs7doxIwkCXXbnkLT62ImkHntWw_TenWYaND6D0fF6Yt9zQ9Rn6aBuATXkjPxkZU0oD8Zl81FFit8EH-Wh2cfnK1jhzAavbHX6rqQsZoXGRJS7uKwjcG4P-94w-bTgNIuLRO1zpR-wqeWmxY-udRNCyhXI6uolr7L5MopRLF-bg1KOt891bL_DPm6kSB1rOvAbxRG87rZ4JrV2RNLXdjYIi665BWj4j4hpoDy4XAQispz9IiCHsIp9Oz693_94NNr8YkaiWTaO20LpkACZmJeYZyVQW-5D9HISdNU5NCcpvmEmWkaM7DNdDcRem_jOIxdlSZUSoZ-2HlyM7kznselH9DjFh_Ps5tZFyj0PKIlCWvSOJXyzM602UAA04SeuWg4KTGZBOLlljbLdoGA334nPXZPX0C4wvz8CKZ56k17UaJJawcZpM6G9zE3VHDQOD_blRXxcztfEqb_h9FqqBCxZ_EUCqHAMKKDBkm3lobCAgZeE0vRuzFv_xr5L_y4d6cF5-a8LGg","tag":"aj8m5UxQS545NAMph5jogA"}';

const pythonDecryptB =
  '{"ciphertext":"pWS8Hcn1Nkznjc4qgYKpgubfCRqUV0k5cBNfq-vypanaI5myf1tetZg0h_mrdSAr60zlBdvlYPGThOkiCPTA6IEyFoZLOumWJpOnqSVYeTvNru7mFCEEReopcxCGr_cGa5qdY2dTll_hAdajgi9pf3hI7fqum_alMQRgyLm48dq2bt7-Ct13dFfxloN7xqXigZ6WpevIRBmG7SS1TlwVTKE5o3UJSPvrA1QTjw7zrIEoLhX5qBmsHKiPFhoWl99Kcegy1hw6-tSbMVNyhtXJ2zBanGv1UNTfwFswonb58fASdpIFyV-L5rziBHBjDLjwVnn4ue8klCh6N4cfE9pJeknTKwN77z0Tv2o197xXWrQE7XL4DzTZ4Osia6mMqZISqHHH1J4iLb9lMdyCqX2caCVn_z-6JR1KTPNeli-Yk4rORfF1_tIceusr7tpizOuXOuRo433tX-wnZbszijUsyxxAcecXGzrzdM6JFJ2c7K1P4pnvmbxoFy2A00kna6ngPC2_U786YA3cqv7etGm3dhyFh39jgRwkl6c_inAcJSiG8DiMd_L8C4-tl0SZiLPuiZlH_BqKNVKZxFsDcEukEQT3liOxPlf6qfD4ft91VQMmbIDP3Gh763mVxKwPyhzANLO0JBCJmqTsJ3mz_j69Y5o1Vl4QzC0K9TWSK-UqogS6SSAJkTig7aAHIFMaBcu2Jufnqb6SwoyU-TIoaRdW0FhDrWniDX58V9b5ZdtSfYUdNGE1BIv0r1yw6tFDxxA6Ac9tpHOpBrlzvOqtcGvdSxCjIqUgs4E9qINFiLIm0NY3qFZkldLFbUCcxnNOVc0DufgRYQjxZz5eomLQpnGUYalzScyqthFLXJGgXBmgyv9Bc8AViUfH5TKkm0pbSkC44JFGKIuziS4VJLNa4utNmJUc7aRnuIbo","encrypted_key":"7Xya-GDO6_6V92CKqUc4oDHjUw42OVxlVG7uXRpSxF6UI1UjbaN3ng","header":{"epk":{"crv":"P-256","kty":"EC","x":"XuKzZf8TTa_uMypUIl_2TkCLl3SdhaBCKXD9a0gqNZ4","y":"yLcI0MG3ifn0uxA9KJpZo6nK2lYJp_bCQTE4tyWuyCE"}},"iv":"osrx9JwPuu50zzsP","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJvd25lciI6InJlY2VpdmVyIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciJdfQ","tag":"A6aaBM6OAOT_6GtK6osRZA"}';

const pythonDecryptAB =
  '{"ciphertext":"sxKCnul4mdreZlqPKsIQS-1ynl2NxI8_YWR-pWy3zARg0Utu4CkPgnaNz1cMKKxCrS2qk_CFPfW-WaCHtHLHIaAAx7FDP_scLBl7dIw9hLw2A4XqsB_qNn-Cq8tv-PnxYgxylTSzs-FZUKLU1UoNvqeuGe25FixqBF4gRinsHVqSCUskuvFCkJU5_JZdl-Ge2ROhSrVS5drOYh_DsWaqxDpOwCqnOXw_9636UmMDfkSRR8IK6EYlFov2D2a-1ymNoiMu_kAyY-_ADpA1Y9IHO_wKSSpbOay84Pok4Qv_YYBLtNtIUgWAvDNozyQTvAN5OWQdDhjQDEeL0OVBASnB7TvDsgajVUZQx50_auNgiDofOpcURSG46DIj9PdQg4hl-MPCalMY2-lSRNP8R-g7joeiE_chVb_nlzJJk5aZPUmHjtYSDrPgtegJwKeQ5Bbb5uOcEcktSz5kKEuPTxxBLJj6ZiJw6WwJKJavfz8feU4CzTPQO8x4yA6CIUS_rqjqxK2nnZMB-RWkyaeH85yq58wtVv_WfS3bjxRMPKwfYwHTn1CQ5Uar5k83LCyCpSFKp_mIcyNICO7bpRgMUweiVxQUtyZvBgk7J4xpB3EBPzDH_70ugJgvLy6vZqZr8KjlU9PqlOLYnTN-qr8LFq77Mv9d4-V_h6P9sBT24tVYf7fCnBeQJx7MPJ2dUkRwi9pPCPWoLPBDGSbCoZ0oeypYROs43SHmp4o-rw26oyIeyQZRRvMyIsaaGvCR4SlRLpNVx0iNk9vlzplZaBXhFmtkHkw4niZYX2rUYwmYkEHC8aq5g8mBLt4T6ZlDIzXqIzFg1KdbTQBx4g_8905ymlqfJRFuu8OjMA5NiQ40imyUveCgTD2UhbxsuHo51FcmciSO4rA0i_YcpOliRHtj1fTkui_cUnN7wpo9m-MHtP_CpU4i6-iSWZs","iv":"w0Nr5LU6H82F1sS8","protected":"eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJvd25lciI6InJlY2VpdmVyIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciIsInNlbmRlciJdfQ","recipients":[{"encrypted_key":"goNY0215cDhcB2odbLrBZvSwZRsztiWnrHKbMhPUHww6uKbfIF6FYA","header":{"epk":{"crv":"P-256","kty":"EC","x":"G-xLQ0ztb5_2nq6XNtI2cYvhROq_UbUcq-HmKCM80Qc","y":"vTedBciY6jdxU-CJqeM27cd_UMkWnyzAtwJMj1EQjSM"}}},{"encrypted_key":"qHqM2NsL5AT843Y0_FNpyMz8VA6q190sJXlUT5qLJm6UX65lPWceeQ","header":{"epk":{"crv":"P-256","kty":"EC","x":"ViVuZRu9g0KEeb5Jq5zKo0QAdTKXVx0ER2sAkDr1Plw","y":"3LI9GfPXL1gYxGtcmbSFEyiytpAcnQU4tzIdf8c4vZQ"}}}],"tag":"M1METSPd_J7-dfAwdCgaVQ"}';

const jsDecryptB =
  '{"ciphertext":"m_VmFwI7F7gT9Ox_0u4eR3JanemQ4QpuJ-3axIpuQXPJWVpStsqSXHNsu7HTRhjr0hIy2ks9SV4kaRkAGmrUsaZ7yQqY5zbUp_5hQ2y-xaOo-3eLwo-c7wqGmHpv0UsLJWQkTpLvDJeqsa9p_lX0bq72t5Cm_QsTTyUhDfO9FazNdbNdTBYm8bSnqZ7-_Xs-uTEK8mfAOr4CvhLLUBcjxwGKnKipUnlP1SbWqofRgwoJIFdT5O8aJ1L5UZvWhADkQsxYceyjWlj_k3JXHHF5BDbkSYdExY__snBvBSTfKXUBiCo2JhwlgWXuUnRRVJqVSwbNkYd_l54qcurV_50eoe7VkM1wnM0YZ9fvbIY_39kyYoGBPAHTln-FUnsGEAZrq4bOPJuZAxzxtQZQMj39msKpWQ0AGaZHzvFGPBMo0osnDlthzu6mJ-3qAvag714yY-W7rk7U0gkPkfTZqILcHZ7OSYD6annaOsqH4dQ9TWSY8dI-CQk_DNIURyDM5SvVcnJAWTP4QZI9VpWWgPxzbdximm4lxBUrXmQbRbfR09mI4KGybeeWxJ99XKSKLQyCFMHiDZonmNB853BFkp3isEuA52IC7_YLJ5rgyszaJ_g2zAXtXeLDNEaOhtYa2HVCQEgs1f8xC-TsQTXkvBrVosJ7Aj3EQIaNOic9qkE4rK2uTG0Z3hP1_7U_z_HXIP4DPvg1A_TAb_l71LPgit8h7CKuhmuVJjdwKLUhbhgPcwOOLQEmoSEby--VlLUlW_of9q0EzcXYkn3mNjUzBFURWwCSizqOeRibsbzUaZYVg7o-FciKGEmhPfk1HMXRMnZFH0kPxGqaV98JiuEYEC4Tp1-kYNhwnQYYQlyxMlsZt0rLL4dKAyCAH5OW3kfo9VdGPhJj4T3lMg3bl8dYGX_EH0vtynPv_W4t7O6HnqlJ","iv":"jqhsbZU8KWp8lLQ1","recipients":[{"encrypted_key":"_lJCgn2a5YhXcTspsxIZFTebZOao1fKBya4efLS_sxchviuBW5zE0g","header":{"alg":"ECDH-ES+A256KW"}}],"tag":"5HOYDjKyLZMB93njPHY-PQ","protected":"eyJlbmMiOiJBMjU2R0NNIiwicmVjaXBpZW50cyI6WyJyZWNlaXZlciJdLCJvd25lciI6InJlY2VpdmVyIiwiZXBrIjp7IngiOiJSTlhCbWRCMVJfQWgzZW1oVWh1Z3RzWFFvcjZDV2tHQ05VeWw4SjRNZUprIiwiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsInkiOiI4Q09MVjFPaTJjaG1DUGU5eUpCTW81MjNMb3pPZERqUk13N2lwb0Q3Yks4In19"}';

const jsDecryptAB =
  '{"ciphertext":"2DuUFjjm2c-8EKuWi4QtOM6H4UW2ThQNknyO49QKiAKXfjfju4eHrxz4Qj0GQUXiijvJnV4RR_NGmKK5V0mrdeibhwUMUMpnmXepNdaBrpWJBOlW3ysSuvC-w2guAm6eutauA0R2I7ec94pLGwjapkqqL_xtWKnj3Vds4wejwSCm58uvt8uk9NxnMd2BivwQU1cPDBAZfVL3orln9Z9X3v9Z1fDCuP2c6dK-6fq8WOFvyDFmtEqqQp3D0QGg-FJhC7KQUJucwSkTkI6UbVpLMOtXRlY_lQXt24b3wQC7J-OW-K14T2lul8Wz5g73UxQcmokCrTLnkApsqJhJarOx9hNfMGiUl49Z448WtIkRWFO98TXoWtLnZOI2s0JbeMsxnbS6eIWuI8j3WCYf9zVgLkEayD-wW0EANRxTiw_strzLqhLw21jPA7JstGMuEf710LRZcNwe-p4LvSDW-eAWzsXPs9DGEF6cflsJruouH9eOc6zusAxs1PWbJ6Ju6bG1g9xmt1y7cDcEs8ShIHM_cjkPiww-JgYGyegUNMYHnlM5xdAAzfBbT_jBYylhlvZdy_XoKHW1A28_zbUZ54Bg-qJG3GW8-aZsYRJ-RmPKz3c1oEv_72qu8PJF0QJljs3ZPlfmHwL99nKNasTM-f6QShVclmadOPWOnwYBSaqlaUiEqCq_G_e5j2JjduFsEqvH1DJvDxjaq5nnR9Qdg3--hF9oNALioaf9gA5kjEtKyl3UKu3WhyAIxMzQiYDB_XOVUVKxDSVd2M0r_batlQm7FeJA4XGIAS2j7sLhf7c2PwmadJQPl9GpYHtz2s1J8bbKPxmWhCvhN8UNDxraWTxj0jS82TUv_lS2YrVJHqP04OORILrm3QFWGMTx7LLSmKm6yVlHvdvvDqbAEEGiL36TQps507rBB7Or2w391zCSNgc7IRw7wlIB1WuOIsi0","iv":"3oxBJNI4bvXLU4m4","recipients":[{"encrypted_key":"c20fUmdbEczdvRLfKL9itXv08mT22MUirp89cNe2xxCTiYoV4_wFDw","header":{"alg":"ECDH-ES+A256KW","epk":{"x":"N-H0jwy0K3AvNO1PBoczKyQdPyhEiQ1DtV1r-KPl76o","crv":"P-256","kty":"EC","y":"iHwZdLn5kBmlo-Z03TlzLUjTmAEQ0M4VDN2Ry7zjs_A"}}},{"encrypted_key":"177IKXct_Yc_UXIo9LVYjojvx4rm1wz29ps88Z47Q74wnSSYEdX-ng","header":{"alg":"ECDH-ES+A256KW","epk":{"x":"YMyLStWS7RWBWTMtBx5a27wu7VChIKD2vuSmnUgaaqg","crv":"P-256","kty":"EC","y":"mOeA_klE_ynjnpjXlihpy25OFlK0TcrCzcHaPz4-_1Q"}}}],"tag":"LbmchWv7PaJABuMRmI0Qcw","protected":"eyJlbmMiOiJBMjU2R0NNIiwicmVjaXBpZW50cyI6WyJzZW5kZXIiLCJyZWNlaXZlciJdLCJvd25lciI6InJlY2VpdmVyIn0"}';

let senderPromise = UserManagement.importAuthenticatedUser(
  'sender',
  TestKeys.pubA,
  TestKeys.pubA,
  TestKeys.privA,
  TestKeys.privA
);

let receiverPromise = UserManagement.importAuthenticatedUser(
  'receiver',
  TestKeys.pubB,
  TestKeys.pubB,
  TestKeys.privB,
  TestKeys.privB
);

describe('Test compatibility with go-it-crypto', () => {
  test('Decrypt JWE for single receiver', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await receiver.decrypt(goDecryptB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('go-it-crypto');
  });
  test('Decrypt JWE for multiple receivers', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await sender.decrypt(goDecryptAB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('go-it-crypto');

    signedLog = await receiver.decrypt(goDecryptAB, fetchUser);
    accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('go-it-crypto');
  });
});

describe('Test compatibility with py-it-crypto', () => {
  test('Decrypt JWE for single receiver', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await receiver.decrypt(pythonDecryptB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('py-it-crypto');
  });
  test('Decrypt JWE for multiple receivers', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await sender.decrypt(pythonDecryptAB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('py-it-crypto');

    signedLog = await receiver.decrypt(pythonDecryptAB, fetchUser);
    accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('py-it-crypto');
  });
});

describe('Test compatibility with js-it-crypto', () => {
  test('Decrypt JWE for single receiver', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await receiver.decrypt(jsDecryptB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('js-it-crypto');
  });
  test('Decrypt JWE for multiple receivers', async () => {
    let sender = await senderPromise;
    let receiver = await receiverPromise;

    let fetchUser = createFetchSender([sender, receiver]);

    let signedLog = await sender.decrypt(jsDecryptAB, fetchUser);
    let accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('js-it-crypto');

    signedLog = await receiver.decrypt(jsDecryptAB, fetchUser);
    accessLog = signedLog.extract();
    expect(accessLog.justification).toBe('js-it-crypto');
  });
});

test('Compute tokens for compatibility tests', async () => {
  let sender = await senderPromise;
  let receiver = await receiverPromise;

  let log = await sender.signAccessLog(
    new AccessLog(sender.id, receiver.id, 'tool', 'js-it-crypto', 30, 'ts-it-crypto', [
      'email',
      'address',
    ])
  );

  let jsDecryptB = await sender.encrypt(log, [receiver]);
  let jsDecryptAB = await receiver.encrypt(log, [sender, receiver]);
  console.log(jsDecryptB);
  console.log(jsDecryptAB);
});
