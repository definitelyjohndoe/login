      $(document).ready(function(){
        grecaptcha.ready(function() {
          grecaptcha.execute('6LfUA-gsAAAAAJrvkh8XqXpdMbXndA6UoldDheC2', {action: 'submit'}).then(function(token) {
              $.post('/capveri',{t:token},function(res,stat){
		
	      });
          });
        });
      });
