          fetch(url,{
              method:"get",
              headers:{
                  "Accept:":"application/json"
              }
          })
          .then(function (response){
                if (response.status == 200){
                    return response;
                }
            })
            .then(function (data) {
              return data.text();
            })
            .then(function(text){
                console.log("请求成功，响应数据为:",text);
            })
            .catch(function(err){
                console.log("Fetch错误:"+err);
            });