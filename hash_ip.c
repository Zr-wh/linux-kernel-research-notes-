/******************************************************************************

                  ��Ȩ���� (C), 2001-2011, ��Ϊ�������޹�˾

 ******************************************************************************
  �� �� ��   : hash_ip.c
  �� �� ��   : ����
  ��    ��   : 
  ��������   : 2023��4��13��
  ����޸�   :
  ��������   : �����Ϊhi3660��ip��ַ��ϣӳ�䵽mac��ַ��ʵ��
  �����б�   :
  �޸���ʷ   :


******************************************************************************/



//ÿ����ϣ�ڵ�ά���Ľṹ�壬����ip��ַ��mac��ַ��ӳ���ϵ
typedef struct
{
    oal_dlist_head_stru     st_entry;                       /* �ýṹ��������� */
    oal_uint32              ul_ipv4;                        /* ��¼��Ӧ��ipv4��ַ */
    oal_uint8               auc_mac[WLAN_MAC_ADDR_LEN];     /* ��¼��Ӧ��mac��ַ */
    oal_uint8               auc_rsv[2];
    //������ά�������Ϣ����ip��ַ��Ӧ��������Ϣ����ֻ��mac��ַ
}hmac_proxy_ipv4_hash_stru;

/* �����û��������� */
#define WLAN_ASSOC_USER_MAX_NUM_LIMIT       8
#define MAC_VAP_USER_HASH_INVALID_VALUE      0xFFFFFFFF                         /* HSAH�Ƿ�ֵ */
#define MAC_VAP_USER_HASH_MAX_VALUE         (WLAN_ASSOC_USER_MAX_NUM_LIMIT * 2)       /* 2Ϊ��չ���� */


/* �����û��������� 16*/
#define HMAC_PROXY_IPV4_HASHSIZE        MAC_VAP_USER_HASH_MAX_VALUE
// #define HMAC_PROXY_IPV6_HASHSIZE        MAC_VAP_USER_HASH_MAX_VALUE

//nΪipv4��ַ��ȡipv4��ַ�����һ���ֽڣ���192.168.1.3��ȡ3
#define HMAC_PROXY_IPV4_HASH(n) \
        (((const oal_uint8 *)(&n))[3] % HMAC_PROXY_IPV4_HASHSIZE)

// #define HMAC_PROXY_IPV6_HASH(n) \
//         (((const oal_uint8 *)(n))[15] % HMAC_PROXY_IPV6_HASHSIZE)


/*��Ϊhi3386ά���� VAP�����ݽṹ */
typedef struct
{                           
   mac_vap_proxyarp_stru              *pst_vap_proxyarp;    /* ����arp�Ľṹ�� */

}mac_vap_stru;

//����arp�Ľṹ�壬��16����ϣ���ÿ����ϣ����ά��һ�������������е�ÿ���ڵ㶼��һ���û�����Ϣ
typedef struct
{
    oal_dlist_head_stru                 ast_ipv4_head[MAC_VAP_USER_HASH_MAX_VALUE];
    oal_dlist_head_stru                 ast_ipv6_head[MAC_VAP_USER_HASH_MAX_VALUE];
    oal_bool_enum_uint8                 en_is_proxyarp;
    oal_uint8                           uc_ipv4_num;        /* ��¼ipv4������ */
    oal_uint8                           uc_ipv6_num;        /* ��¼ipv6������ */
}mac_vap_proxyarp_stru;


//��ʼ����ϣ�ڵ�����ݽṹ��һ��16��
oal_void hmac_proxy_arp_init(mac_vap_stru *pst_mac_vap)
{
    oal_uint32              ul_loop = 0;

   
    if ((WLAN_VAP_MODE_BSS_AP != pst_mac_vap->en_vap_mode)
     || (OAL_PTR_NULL != pst_mac_vap->pst_vap_proxyarp))
    {
        return;
    }


    /* �����ϣ�ڵ�������ڴ� ��*/
    pst_mac_vap->pst_vap_proxyarp = OAL_MEM_ALLOC(OAL_MEM_POOL_ID_LOCAL, OAL_SIZEOF(mac_vap_proxyarp_stru), OAL_TRUE);
    if (OAL_PTR_NULL == pst_mac_vap->pst_vap_proxyarp)
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "hmac_proxy_arp_init err! malloc err!");
        return;
    }

    OAL_MEMZERO(pst_mac_vap->pst_vap_proxyarp, OAL_SIZEOF(mac_vap_proxyarp_stru));

   //16����ϣ���������ͷ��ʼ��
    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        oal_dlist_init_head(&(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_loop]));
    }

    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        oal_dlist_init_head(&(pst_mac_vap->pst_vap_proxyarp->ast_ipv6_head[ul_loop]));
    }
}


//ͨ��ipv4�ĵ�ַ��ϣӳ�䣬���Ҷ�Ӧ��mac��ַ
oal_err_code_enum_uint32 hmac_proxy_get_mac_by_ipv4(mac_vap_stru *pst_mac_vap, oal_uint32 ul_ipv4, oal_uint8 *puc_mac)
{
    oal_uint32                  ul_user_hash_value;
    hmac_proxy_ipv4_hash_stru  *pst_hash;
    oal_dlist_head_stru        *pst_entry;

    if (OAL_UNLIKELY((OAL_PTR_NULL == pst_mac_vap)
                  || (OAL_PTR_NULL == puc_mac)))
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "{mac_vap_find_user_by_macaddr::param null.}");

        return OAL_ERR_CODE_PTR_NULL;
    }

    //����ipv4��ַ�Ĺ�ϣֵ
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);

    //�����ù�ϣֵ��Ӧ�����������Ҷ�Ӧ��ipv4��ַ
    OAL_DLIST_SEARCH_FOR_EACH(pst_entry, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]))
    {
        pst_hash = (hmac_proxy_ipv4_hash_stru *)pst_entry;
        //����ҵ��˶�Ӧ��ipv4��ַ���ͽ�mac��ַ������puc_mac��
        if (pst_hash->ul_ipv4 != ul_ipv4)
        {
            continue;
        }

        oal_memcopy(puc_mac, pst_hash->auc_mac, WLAN_MAC_ADDR_LEN);

        return OAL_SUCC;
    }

    return OAL_FAIL;
}
//��ipv4�ĵ�ַ��hash����ɾ��
oal_err_code_enum_uint32 hmac_proxy_remove_ipv4(mac_vap_stru *pst_mac_vap, oal_uint32 ul_ipv4)
{
    oal_uint32                  ul_user_hash_value;
    oal_dlist_head_stru        *pst_entry;
    hmac_proxy_ipv4_hash_stru  *pst_hash;
    oal_dlist_head_stru        *pst_dlist_tmp      = OAL_PTR_NULL;

    if (OAL_UNLIKELY(OAL_PTR_NULL == pst_mac_vap))
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "{hmac_proxy_remove_ipv4::param null.}");
        return OAL_ERR_CODE_PTR_NULL;
    }

    if (0 == pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num)
    {
        return OAL_SUCC;
    }
    
    //����ipv4��ַ�Ĺ�ϣֵ
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);
    //�����ù�ϣֵ��Ӧ�����������Ҷ�Ӧ��ipv4��ַ
    OAL_DLIST_SEARCH_FOR_EACH_SAFE(pst_entry, pst_dlist_tmp, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]))
    {
        pst_hash = (hmac_proxy_ipv4_hash_stru *)pst_entry;
        //����ҵ��˶�Ӧ��ipv4��ַ���ͽ��ýڵ��������ɾ�������ͷ��ڴ�
        if (pst_hash->ul_ipv4 != ul_ipv4)
        {
            continue;
        }
        oal_dlist_delete_entry(pst_entry);
        OAL_MEM_FREE(pst_hash, OAL_TRUE);
        pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num--;
        return OAL_SUCC;
    }

    return OAL_SUCC;
}

//��ipv4�ĵ�ַ����hash��������¼��Ӧ��mac��ַ
oal_err_code_enum_uint32 hmac_proxy_add_ipv4(mac_vap_stru *pst_mac_vap, oal_uint32 ul_ipv4, oal_uint8 *puc_mac)
{
    oal_uint32                  ul_user_hash_value;
    hmac_proxy_ipv4_hash_stru  *pst_hash;
    oal_err_code_enum_uint32    en_exist;
    oal_uint8                   auc_mac[OAL_MAC_ADDR_LEN];

    if (OAL_UNLIKELY((OAL_PTR_NULL == pst_mac_vap)
                  || (OAL_PTR_NULL == puc_mac)))
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "{hmac_proxy_add_ipv4::param null.}");

        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ��ѯ�Ƿ���� */
    en_exist = hmac_proxy_get_mac_by_ipv4(pst_mac_vap, ul_ipv4, auc_mac);
    if (OAL_SUCC == en_exist)
    {
        if (!oal_memcmp(auc_mac, puc_mac, OAL_MAC_ADDR_LEN))
        {
            return OAL_SUCC;
        }
        /* ������Բ�ͬ��mac����ǰ���¼�Ľ��ɾ�����������̽��µĽ����� */
        hmac_proxy_remove_ipv4(pst_mac_vap, ul_ipv4);
    }

    if (MAC_VAP_USER_HASH_MAX_VALUE <= pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num)
    {
        return OAL_ERR_CODE_ARRAY_OVERFLOW;
    }

    /* �����ڴ� */
    pst_hash = OAL_MEM_ALLOC(OAL_MEM_POOL_ID_LOCAL, OAL_SIZEOF(hmac_proxy_ipv4_hash_stru), OAL_TRUE);
    if (OAL_PTR_NULL == pst_hash)
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "hmac_proxy_add_ipv4 err! melloc err!");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* ��д */
    pst_hash->ul_ipv4 = ul_ipv4;
    oal_memcopy(pst_hash->auc_mac, puc_mac, OAL_MAC_ADDR_LEN);

    /* ����hash�� */
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);
    oal_dlist_add_head(&(pst_hash->st_entry), &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]));
    //��¼ipv4��ַ�ĸ���
    pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num++;

    return OAL_SUCC;
}


//ɾ����ϣ�ڵ�����ݽṹ��һ��16��
oal_void hmac_proxy_exit(mac_vap_stru *pst_mac_vap)
{
    oal_dlist_head_stru        *pst_entry;
    hmac_proxy_ipv4_hash_stru  *pst_hash_ipv4;
    hmac_proxy_ipv6_hash_stru  *pst_hash_ipv6;
    oal_dlist_head_stru        *pst_dlist_tmp      = OAL_PTR_NULL;
    oal_uint32                  ul_loop = 0;

    if (WLAN_VAP_MODE_BSS_AP != pst_mac_vap->en_vap_mode
     || (OAL_PTR_NULL == pst_mac_vap->pst_vap_proxyarp))
    {
        return;
    }
    //ɾ��ipv4�Ĺ�ϣ�ڵ�
    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        OAL_DLIST_SEARCH_FOR_EACH_SAFE(pst_entry, pst_dlist_tmp, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_loop]))
        {
            pst_hash_ipv4 = (hmac_proxy_ipv4_hash_stru *)pst_entry;
            oal_dlist_delete_entry(pst_entry);
            OAL_MEM_FREE(pst_hash_ipv4, OAL_TRUE);
            pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num--;
        }
    }

    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        OAL_DLIST_SEARCH_FOR_EACH_SAFE(pst_entry, pst_dlist_tmp, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv6_head[ul_loop]))
        {
            pst_hash_ipv6 = (hmac_proxy_ipv6_hash_stru *)pst_entry;
            oal_dlist_delete_entry(pst_entry);
            OAL_MEM_FREE(pst_hash_ipv6, OAL_TRUE);
            pst_mac_vap->pst_vap_proxyarp->uc_ipv6_num--;
        }
    }

    OAL_MEM_FREE(pst_mac_vap->pst_vap_proxyarp, OAL_TRUE);
    pst_mac_vap->pst_vap_proxyarp = OAL_PTR_NULL;

}