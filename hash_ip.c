/******************************************************************************

                  版权所有 (C), 2001-2011, 华为技术有限公司

 ******************************************************************************
  文 件 名   : hash_ip.c
  版 本 号   : 初稿
  作    者   : 
  生成日期   : 2023年4月13日
  最近修改   :
  功能描述   : 解读华为hi3660的ip地址哈希映射到mac地址的实现
  函数列表   :
  修改历史   :


******************************************************************************/



//每个哈希节点维护的结构体，建立ip地址和mac地址的映射关系
typedef struct
{
    oal_dlist_head_stru     st_entry;                       /* 该结构体的链表项 */
    oal_uint32              ul_ipv4;                        /* 记录对应的ipv4地址 */
    oal_uint8               auc_mac[WLAN_MAC_ADDR_LEN];     /* 记录对应的mac地址 */
    oal_uint8               auc_rsv[2];
    //还可以维护多个信息，即ip地址对应的其它信息，不只是mac地址
}hmac_proxy_ipv4_hash_stru;

/* 关联用户的最大个数 */
#define WLAN_ASSOC_USER_MAX_NUM_LIMIT       8
#define MAC_VAP_USER_HASH_INVALID_VALUE      0xFFFFFFFF                         /* HSAH非法值 */
#define MAC_VAP_USER_HASH_MAX_VALUE         (WLAN_ASSOC_USER_MAX_NUM_LIMIT * 2)       /* 2为扩展因子 */


/* 代理用户的最大个数 16*/
#define HMAC_PROXY_IPV4_HASHSIZE        MAC_VAP_USER_HASH_MAX_VALUE
// #define HMAC_PROXY_IPV6_HASHSIZE        MAC_VAP_USER_HASH_MAX_VALUE

//n为ipv4地址，取ipv4地址的最后一个字节，如192.168.1.3，取3
#define HMAC_PROXY_IPV4_HASH(n) \
        (((const oal_uint8 *)(&n))[3] % HMAC_PROXY_IPV4_HASHSIZE)

// #define HMAC_PROXY_IPV6_HASH(n) \
//         (((const oal_uint8 *)(n))[15] % HMAC_PROXY_IPV6_HASHSIZE)


/*华为hi3386维护的 VAP的数据结构 */
typedef struct
{                           
   mac_vap_proxyarp_stru              *pst_vap_proxyarp;    /* 代理arp的结构体 */

}mac_vap_stru;

//代理arp的结构体，有16个哈希表项，每个哈希表项维护一个链表，链表中的每个节点都是一个用户的信息
typedef struct
{
    oal_dlist_head_stru                 ast_ipv4_head[MAC_VAP_USER_HASH_MAX_VALUE];
    oal_dlist_head_stru                 ast_ipv6_head[MAC_VAP_USER_HASH_MAX_VALUE];
    oal_bool_enum_uint8                 en_is_proxyarp;
    oal_uint8                           uc_ipv4_num;        /* 记录ipv4的条数 */
    oal_uint8                           uc_ipv6_num;        /* 记录ipv6的条数 */
}mac_vap_proxyarp_stru;


//初始化哈希节点的数据结构，一共16个
oal_void hmac_proxy_arp_init(mac_vap_stru *pst_mac_vap)
{
    oal_uint32              ul_loop = 0;

   
    if ((WLAN_VAP_MODE_BSS_AP != pst_mac_vap->en_vap_mode)
     || (OAL_PTR_NULL != pst_mac_vap->pst_vap_proxyarp))
    {
        return;
    }


    /* 申请哈希节点的所有内存 ，*/
    pst_mac_vap->pst_vap_proxyarp = OAL_MEM_ALLOC(OAL_MEM_POOL_ID_LOCAL, OAL_SIZEOF(mac_vap_proxyarp_stru), OAL_TRUE);
    if (OAL_PTR_NULL == pst_mac_vap->pst_vap_proxyarp)
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "hmac_proxy_arp_init err! malloc err!");
        return;
    }

    OAL_MEMZERO(pst_mac_vap->pst_vap_proxyarp, OAL_SIZEOF(mac_vap_proxyarp_stru));

   //16个哈希表项的链表头初始化
    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        oal_dlist_init_head(&(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_loop]));
    }

    for (ul_loop = 0; ul_loop < MAC_VAP_USER_HASH_MAX_VALUE; ul_loop++)
    {
        oal_dlist_init_head(&(pst_mac_vap->pst_vap_proxyarp->ast_ipv6_head[ul_loop]));
    }
}


//通过ipv4的地址哈希映射，查找对应的mac地址
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

    //计算ipv4地址的哈希值
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);

    //遍历该哈希值对应的链表，查找对应的ipv4地址
    OAL_DLIST_SEARCH_FOR_EACH(pst_entry, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]))
    {
        pst_hash = (hmac_proxy_ipv4_hash_stru *)pst_entry;
        //如果找到了对应的ipv4地址，就将mac地址拷贝到puc_mac中
        if (pst_hash->ul_ipv4 != ul_ipv4)
        {
            continue;
        }

        oal_memcopy(puc_mac, pst_hash->auc_mac, WLAN_MAC_ADDR_LEN);

        return OAL_SUCC;
    }

    return OAL_FAIL;
}
//将ipv4的地址从hash表中删除
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
    
    //计算ipv4地址的哈希值
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);
    //遍历该哈希值对应的链表，查找对应的ipv4地址
    OAL_DLIST_SEARCH_FOR_EACH_SAFE(pst_entry, pst_dlist_tmp, &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]))
    {
        pst_hash = (hmac_proxy_ipv4_hash_stru *)pst_entry;
        //如果找到了对应的ipv4地址，就将该节点从链表中删除，并释放内存
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

//将ipv4的地址加入hash表，并记录相应的mac地址
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

    /* 查询是否存在 */
    en_exist = hmac_proxy_get_mac_by_ipv4(pst_mac_vap, ul_ipv4, auc_mac);
    if (OAL_SUCC == en_exist)
    {
        if (!oal_memcmp(auc_mac, puc_mac, OAL_MAC_ADDR_LEN))
        {
            return OAL_SUCC;
        }
        /* 如果来自不同的mac，则将前面记录的结点删除，后面流程将新的结点加入 */
        hmac_proxy_remove_ipv4(pst_mac_vap, ul_ipv4);
    }

    if (MAC_VAP_USER_HASH_MAX_VALUE <= pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num)
    {
        return OAL_ERR_CODE_ARRAY_OVERFLOW;
    }

    /* 申请内存 */
    pst_hash = OAL_MEM_ALLOC(OAL_MEM_POOL_ID_LOCAL, OAL_SIZEOF(hmac_proxy_ipv4_hash_stru), OAL_TRUE);
    if (OAL_PTR_NULL == pst_hash)
    {
        OAM_ERROR_LOG0(0, OAM_SF_PROXYARP, "hmac_proxy_add_ipv4 err! melloc err!");
        return OAL_ERR_CODE_PTR_NULL;
    }

    /* 填写 */
    pst_hash->ul_ipv4 = ul_ipv4;
    oal_memcopy(pst_hash->auc_mac, puc_mac, OAL_MAC_ADDR_LEN);

    /* 加入hash表 */
    ul_user_hash_value = HMAC_PROXY_IPV4_HASH(ul_ipv4);
    oal_dlist_add_head(&(pst_hash->st_entry), &(pst_mac_vap->pst_vap_proxyarp->ast_ipv4_head[ul_user_hash_value]));
    //记录ipv4地址的个数
    pst_mac_vap->pst_vap_proxyarp->uc_ipv4_num++;

    return OAL_SUCC;
}


//删除哈希节点的数据结构，一共16个
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
    //删除ipv4的哈希节点
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